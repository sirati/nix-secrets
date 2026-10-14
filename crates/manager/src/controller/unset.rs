//! Unset stored values at deployment time.
//!
//! Before a deployment every unset stored leaf is classified. If any cannot be
//! generated the whole deployment is refused with one list, before anything
//! is generated or written. Otherwise the target generates the rest, installs
//! them, and returns only ciphertext, which is checked without decrypting and
//! stored through the backend's conditional write.

use super::*;
use nix_secrets_core::schema::deployment_generator;
use nix_secrets_crypto::verify_ssh_recipient_header;
use nix_secrets_transport::{GenerateEntry, GeneratedRecord};
use std::collections::BTreeMap;

/// How a deployment treats its unset stored values.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UnsetPlan {
    /// Identifier and generator label of each value the target generates.
    pub generate: Vec<(String, String)>,
    /// Identifier and reason of each value that must be entered first.
    pub missing: Vec<(String, String)>,
    /// Derived values and their sources, deployed from the source's value.
    pub derived: Vec<(String, String)>,
    /// Derived values the target frames itself, because their source is
    /// unset, on the same host, and generated in this deployment.
    pub derived_on_target: Vec<(String, String)>,
    /// Values in `missing` a partial deployment leaves out, which is every
    /// missing value: the target keeps waiting for them.
    pub skippable: Vec<String>,
    /// Why each value in `missing` is missing, for grouping in the dialog.
    pub reasons: BTreeMap<String, MissingKind>,
    /// Unset public information the host installs its declared default for;
    /// never sent, so the installed default stays.
    pub host_default: Vec<String>,
    /// Unset symmetric sources on another host that this target generates
    /// because it deploys first: identifier and generator label. Encrypted
    /// there to the source leaf's recipients and stored here as ciphertext.
    pub shared: Vec<(String, String)>,
}

/// Why a value cannot be deployed yet.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MissingKind {
    /// The operator must enter it.
    NeedsInput,
    /// Intentionally not required by consumers.
    Optional,
    /// A public-key inventory other hosts fill by registering their keys.
    FilledByAnotherHost,
    /// Derived from a value that is unset.
    DerivedFromUnset,
    /// The host cannot receive it yet, found before connecting: a missing
    /// prerequisite on the host or a receiver too old for it.
    CannotDeploy,
    /// Its stored value was published under an older schema. It stays
    /// stored and is never deployed as if valid.
    InvalidUnderSchema,
    /// Selected, but the host's current activation does not declare it.
    NotDeclaredByHost,
    /// The host's current activation declares it differently.
    DeclaredDifferently,
    /// The host's activation asks for it, and this schema does not know it.
    UnknownToSchema,
}

impl MissingKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::NeedsInput => "Needs input",
            Self::Optional => "Optional; not provided",
            Self::FilledByAnotherHost => "Filled by another host",
            Self::DerivedFromUnset => "Derived from unset source",
            Self::CannotDeploy => "Cannot deploy",
            Self::InvalidUnderSchema => "Stored value invalid under the current schema",
            Self::NotDeclaredByHost => "Not declared by the host's activation",
            Self::DeclaredDifferently => "Declared differently by the host",
            Self::UnknownToSchema => "Asked for by the host, unknown to this schema",
        }
    }
}

impl UnsetPlan {
    /// Whether a partial deployment can proceed: something is missing and
    /// every missing value can be left out.
    pub fn partial_possible(&self) -> bool {
        !self.missing.is_empty()
            && self
                .missing
                .iter()
                .all(|(identifier, _)| self.skippable.contains(identifier))
    }

    /// Leaves out what the host's activation disagrees with, from
    /// [`super::target_mismatches`], and what depended on it.
    pub(crate) fn exclude_mismatches(&mut self, mismatches: &[(String, MissingKind, String)]) {
        for (identifier, kind, reason) in mismatches {
            self.generate.retain(|(id, _)| id != identifier);
            self.shared.retain(|(id, _)| id != identifier);
            self.derived.retain(|(id, _)| id != identifier);
            self.derived_on_target.retain(|(id, _)| id != identifier);
            self.host_default.retain(|id| id != identifier);
            self.missing.retain(|(id, _)| id != identifier);
            self.skippable.retain(|id| id != identifier);
            self.miss(identifier, *kind, reason.clone());
        }
        let waiting = self
            .derived_on_target
            .iter()
            .filter(|(_, source)| {
                !self.generate.iter().chain(&self.shared).any(|(id, _)| id == source)
            })
            .cloned()
            .collect::<Vec<_>>();
        for (identifier, source) in waiting {
            self.derived_on_target.retain(|(id, _)| id != &identifier);
            self.miss(
                &identifier,
                MissingKind::CannotDeploy,
                format!("its source {source} is left out of this deployment"),
            );
        }
    }

    pub(crate) fn miss(&mut self, identifier: &str, kind: MissingKind, reason: String) {
        self.missing.push((identifier.to_owned(), reason));
        self.skippable.push(identifier.to_owned());
        self.reasons.insert(identifier.to_owned(), kind);
    }

    /// The refusal of a deployment, or none when `allow_partial` lets it
    /// deploy the rest and list the missing values as skipped.
    pub fn refusal_for(&self, allow_partial: bool) -> Option<String> {
        if allow_partial && self.partial_possible() {
            None
        } else {
            self.refusal()
        }
    }

    /// Also refuses a derived value whose source is unset: its source must be
    /// set, or deployed to its own host first when that host generates it.
    pub fn refusal(&self) -> Option<String> {
        let required = self.missing.iter().filter(|(id, _)| self.reasons.get(id) != Some(&MissingKind::Optional)).collect::<Vec<_>>();
        (!required.is_empty()).then(|| {
            format!(
                "Missing values that must be entered: {}. Nothing was generated or written.",
                required
                    .iter()
                    .map(|(id, reason)| format!("{id} ({reason})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    }
}

/// Classifies the leaves of `identifiers` that are absent from the store.
/// Unset stored values are generated when their format is known; a target
/// task whose operator input is unset is always missing, and so is public
/// information whose shared value is unset (`set` names public information
/// by its identifier when its shared value is stored). Target-local keys need
/// no stored value. `stale` names stored public information the current
/// schema rejects, with why: it is left out and listed, never sent.
pub(crate) fn plan_unset(
    schema: &Schema,
    identifiers: &[String],
    set: &BTreeSet<String>,
    stale: &BTreeMap<String, String>,
) -> Result<UnsetPlan, String> {
    let mut plan = UnsetPlan::default();
    let mut waiting = Vec::new();
    for identifier in identifiers {
        if let Some(reason) = stale.get(identifier) {
            plan.miss(identifier, MissingKind::InvalidUnderSchema, reason.clone());
            continue;
        }
        let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
        let leaf = schema.leaf(&path).map_err(|error| error.to_string())?;
        let optional = match &leaf {
            LeafSpec::Stored(spec) => spec.optional,
            LeafSpec::Generated(spec) => spec.optional,
            LeafSpec::Operator(_) => false,
        };
        let provided = match &leaf {
            LeafSpec::Stored(spec) => spec.derived_from.as_ref().map_or(set.contains(identifier), |source| set.contains(&source.identifier)),
            _ => set.contains(identifier),
        };
        if optional && !provided {
            plan.miss(identifier, MissingKind::Optional, "optional; not provided".into());
            continue;
        }
        if let Ok(LeafSpec::Stored(spec)) = schema.leaf(&path) {
            if let Some(derived) = &spec.derived_from {
                let source = &derived.identifier;
                if set.contains(source) {
                    plan.derived.push((identifier.clone(), source.clone()));
                } else {
                    waiting.push((identifier.clone(), source.clone()));
                }
                continue;
            }
        }
        if set.contains(identifier) {
            continue;
        }
        let spec = match schema.leaf(&path).map_err(|error| error.to_string())? {
            LeafSpec::Stored(spec) => spec,
            // Rejected with a clear message when the request is inspected.
            LeafSpec::Operator(_) => continue,
            LeafSpec::Generated(task) => {
                if task.generated_secret.secret_type
                    != nix_secrets_core::GeneratedSecretType::LocalSshKey
                {
                    plan.miss(
                        identifier,
                        MissingKind::NeedsInput,
                        "task input".to_owned(),
                    );
                }
                continue;
            }
        };
        // `set` names public information whose shared value is stored.
        if matches!(spec.kind, SecretKind::PublicInfo) {
            if spec.install_default_if_missing {
                plan.host_default.push(identifier.clone());
            } else {
                plan.miss(
                    identifier,
                    MissingKind::NeedsInput,
                    "public information is unset; enter it first".to_owned(),
                );
            }
            continue;
        }
        // A public-key inventory is filled by the hosts that register keys
        // into it when they are deployed.
        let producers = schema.registration_producers(identifier);
        if producers.is_empty() && spec.destination.content_type.as_deref() == Some("named-ssh-ed25519-public-keys") {
            plan.miss(identifier, MissingKind::FilledByAnotherHost,
                "no reporting-key producers configured; inventory has no registered senders".into());
            continue;
        }

        if !producers.is_empty() {
            let mut hosts = producers
                .iter()
                .filter_map(|producer| producer.split('.').next())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            hosts.dedup();
            plan.miss(
                identifier,
                MissingKind::FilledByAnotherHost,
                format!("filled when {} deploy", hosts.join(", ")),
            );
            continue;
        }
        match deployment_generator(&spec) {
            Ok(generator) => plan.generate.push((identifier.clone(), generator.label())),
            Err(reason) => plan.miss(
                identifier,
                MissingKind::NeedsInput,
                reason.reason().to_owned(),
            ),
        }
    }
    // An unset source generated in this same request is on the same host
    // (a request names one target), so that target frames the derived value
    // from what it generates, and both land in one atomic generation.
    for (identifier, source) in waiting {
        let same_host = source.split('.').next() == identifier.split('.').next();
        let shareable = !same_host && shared_generator(schema, &source).is_some();
        if plan
            .generate
            .iter()
            .chain(&plan.shared)
            .any(|(generated, _)| generated == &source)
        {
            plan.derived_on_target.push((identifier, source));
        } else if shareable {
            // A symmetric secret of another host: generated here, the host
            // deployed first, and stored under its own identifier.
            let label = shared_generator(schema, &source).expect("checked").label();
            plan.shared.push((source.clone(), label));
            plan.derived_on_target.push((identifier, source));
        } else {
            let reason = source_first(schema, &source);
            plan.miss(&identifier, MissingKind::DerivedFromUnset, reason);
        }
    }
    // What the host's configuration shows it cannot receive yet.
    super::preflight::check(schema, identifiers, set, &mut plan);
    Ok(plan)
}

/// The generator of a source another host may generate first: a stored,
/// generatable symmetric secret. A private key is only ever generated on its
/// own host, so key material with a content type is never shared this way.
pub(crate) fn shared_generator(
    schema: &Schema,
    source: &str,
) -> Option<nix_secrets_core::DeployGenerator> {
    let path = SecretPath::parse(source).ok()?;
    let LeafSpec::Stored(spec) = schema.leaf(&path).ok()? else {
        return None;
    };
    if spec.destination.content_type.is_some() || matches!(spec.kind, SecretKind::PublicInfo) {
        return None;
    }
    deployment_generator(&spec).ok()
}

/// Why a derived value's unset source blocks it, and what to do.
fn source_first(schema: &Schema, source: &str) -> String {
    let generatable = SecretPath::parse(source)
        .ok()
        .and_then(|path| schema.leaf(&path).ok())
        .is_some_and(
            |leaf| matches!(leaf, LeafSpec::Stored(spec) if deployment_generator(&spec).is_ok()),
        );
    let host = source.split('.').next().unwrap_or(source);
    if generatable {
        format!("derived from unset {source}; deploy {host} first, which generates it")
    } else {
        format!("derived from unset {source}; enter {source} first")
    }
}

/// The generator fingerprint the target must report for a stored leaf.
pub(crate) fn expected_generator(spec: &nix_secrets_core::SecretSpec) -> Option<String> {
    deployment_generator(spec)
        .ok()
        .map(|generator| generator.fingerprint())
}

pub(crate) fn generate_entries(
    schema: &Schema,
    plan: &UnsetPlan,
) -> Result<Vec<GenerateEntry>, String> {
    let own = plan.generate.iter().map(|(identifier, _)| (identifier, None));
    let shared = plan.shared.iter().map(|(identifier, _)| {
        let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
        let LeafSpec::Stored(spec) = schema.leaf(&path).map_err(|error| error.to_string())? else {
            return Err(format!("{identifier} is not a stored value"));
        };
        let generator = shared_generator(schema, identifier)
            .ok_or_else(|| format!("{identifier} cannot be generated on another host"))?;
        Ok((
            identifier,
            Some(nix_secrets_transport::SharedSource {
                generator: generator.fingerprint(),
                recipient_ids: spec.recipient_ids,
                recipient_public_keys: spec.recipient_public_keys,
            }),
        ))
    });
    own.map(Ok)
        .chain(shared)
        .map(|item| {
            let (identifier, shared) = item?;
            let contribution = crate::task::fresh_contribution()
                .map_err(|error| format!("OS randomness failed: {error}"))?;
            Ok(GenerateEntry {
                identifier: identifier.clone(),
                client_contribution_base64: STANDARD.encode(&contribution[..]),
                shared,
            })
        })
        .collect()
}

/// Validates a returned record against the schema without decrypting it and
/// converts it into a store envelope.
pub(crate) fn record_envelope(
    schema: &Schema,
    identifier: &str,
    record: &GeneratedRecord,
) -> Result<nix_secrets_core::EncryptedSecret, String> {
    let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
    let LeafSpec::Stored(spec) = schema.leaf(&path).map_err(|error| error.to_string())? else {
        return Err(format!("{identifier}: target returned a record for a task"));
    };
    let fail = |message: &str| format!("{identifier}: target record {message}");
    if record.format_version != 1 {
        return Err(fail("has an unsupported format version"));
    }
    if record.recipient_ids != spec.recipient_ids {
        return Err(fail("names different recipients"));
    }
    let version_id = STANDARD
        .decode(&record.version_id_base64)
        .map_err(|_| fail("has an invalid version"))?;
    if version_id.len() != nix_secrets_crypto::VERSION_ID_SIZE {
        return Err(fail("has an invalid version length"));
    }
    let age_ciphertext = STANDARD
        .decode(&record.age_ciphertext_base64)
        .map_err(|_| fail("has invalid ciphertext encoding"))?;
    let keys = spec
        .recipient_public_keys
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    verify_ssh_recipient_header(&age_ciphertext, &keys)
        .map_err(|error| fail(&format!("failed its recipient check: {error}")))?;
    Ok(nix_secrets_core::EncryptedSecret {
        format_version: record.format_version,
        version_id,
        recipient_ids: record.recipient_ids.clone(),
        recipient_refs: vec![],
        age_ciphertext,
        public_key: None,
    })
}

impl Controller {
    /// Decrypts, in one provider batch, every stored value a deployment
    /// sends and every source of a derived value it sends. With 1Password
    /// this is one authorization for the whole deployment.
    pub(super) fn decrypt_for_deployment(
        &self,
        identifiers: &[String],
        generating: &BTreeSet<&str>,
        derive_on_target: &[String],
        derived: &BTreeMap<String, String>,
        entries: &BTreeMap<String, nix_secrets_core::EncryptedSecret>,
    ) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>, String> {
        let mut wanted = BTreeSet::new();
        for identifier in identifiers {
            if generating.contains(identifier.as_str()) || derive_on_target.contains(identifier) {
                continue;
            }
            if let Some(source) = derived.get(identifier) {
                wanted.insert(source.clone());
                continue;
            }
            // Public information and local keys need no stored value.
            if entries.contains_key(identifier) {
                wanted.insert(identifier.clone());
            }
        }
        let records = wanted
            .iter()
            .map(|identifier| {
                let stored = &entries[identifier];
                (
                    identifier.as_str(),
                    EncryptedSecret {
                        format_version: stored.format_version,
                        version_id: stored.version_id.clone(),
                        recipient_ids: stored.recipient_ids.clone(),
                        age_ciphertext: stored.age_ciphertext.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();
        if records.is_empty() {
            return Ok(BTreeMap::new());
        }
        let borrowed = records
            .iter()
            .map(|(identifier, record)| (*identifier, record))
            .collect::<Vec<_>>();
        let values = nix_secrets_crypto::decrypt_secrets(&borrowed, &self.provider)
            .map_err(|error| error.to_string())?;
        Ok(wanted.into_iter().zip(values).collect())
    }

    /// Decrypts a derived value's source and frames it. The version names the
    /// source version and the framing, so the target replaces the derived
    /// value exactly when either changes.
    pub(super) fn derived_entry(
        &self,
        identifier: &str,
        source: &str,
        entries: &BTreeMap<String, nix_secrets_core::EncryptedSecret>,
        plaintexts: &BTreeMap<String, Zeroizing<Vec<u8>>>,
    ) -> Result<DeployEntry, String> {
        let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
        let LeafSpec::Stored(spec) = self.schema.leaf(&path).map_err(|error| error.to_string())?
        else {
            return Err(format!("{identifier} is not a stored value"));
        };
        let derived = spec
            .derived_from
            .ok_or_else(|| format!("{identifier} is not derived"))?;
        let stored = entries
            .get(source)
            .ok_or_else(|| format!("{identifier}: its source {source} became unset"))?;
        let value = plaintexts
            .get(source)
            .ok_or_else(|| format!("{identifier}: its source {source} was not decrypted"))?;
        let framed = derived
            .frame(value)
            .map_err(|error| format!("{identifier} cannot be derived: {error}"))?;
        Ok(DeployEntry {
            identifier: identifier.to_owned(),
            version_id: derived.version(&stored.version_id),
            contents_base64: STANDARD.encode(framed.as_slice()),
        })
    }

    /// Stores target-generated records only where the value is still unset.
    /// A value entered meanwhile is kept; the next deployment then replaces
    /// the target's copy with it.
    #[cfg(test)]
    pub(super) fn store_generated(
        &mut self,
        records: &BTreeMap<String, GeneratedRecord>,
    ) -> Result<Vec<String>, String> {
        let origin = super::quarantine::Origin {
            host: "host".into(),
            deployment: "test-deployment".into(),
        };
        match self.store_generated_all(&origin, records) {
            (stored, None) => Ok(stored),
            (_, Some(problem)) => Err(problem),
        }
    }

    /// Stores every valid record, quarantines every other one, and says
    /// what was not stored as a value.
    pub(super) fn store_generated_all(
        &mut self,
        origin: &super::quarantine::Origin,
        records: &BTreeMap<String, GeneratedRecord>,
    ) -> (Vec<String>, Option<String>) {
        // One record this schema rejects never costs the others: each valid
        // record is stored, and each rejected one is quarantined.
        let mut stored = Vec::new();
        let mut quarantined = Vec::new();
        let mut conflicts = Vec::new();
        for (identifier, record) in records {
            let envelope = match record_envelope(&self.schema, identifier, record) {
                Ok(envelope) => envelope,
                Err(error) => {
                    quarantined.push(self.quarantine_record(origin, identifier, record, &error));
                    continue;
                }
            };
            let path = match SecretPath::parse(identifier) {
                Ok(path) => path,
                Err(error) => {
                    let reason = format!("{identifier}: {error}");
                    quarantined.push(self.quarantine_record(origin, identifier, record, &reason));
                    continue;
                }
            };
            match self.client.set_envelope_if_version(&path, envelope, None) {
                Ok(()) => stored.push(identifier.clone()),
                Err(error) if error.to_string().contains("version changed") => {
                    // The operator's value wins; the host's copy is kept.
                    conflicts.push(identifier.clone());
                    quarantined.push(self.quarantine_record(
                        origin,
                        identifier,
                        record,
                        "a value was entered in the store while the target generated this one",
                    ));
                }
                Err(error) => {
                    let reason = format!("storing it failed: {error}");
                    quarantined.push(self.quarantine_record(origin, identifier, record, &reason));
                }
            }
        }
        let mut problems = Vec::new();
        if !conflicts.is_empty() {
            problems.push(format!(
                "these were entered in the store meanwhile and kept: {}. \
                 Deploy again to install the stored values.",
                conflicts.join(", ")
            ));
        }
        if !quarantined.is_empty() {
            problems.push(format!(
                "these generated records were not stored as values: {}",
                quarantined.join("; ")
            ));
        }
        let problem = (!problems.is_empty())
            .then(|| format!("Deployed, but {}", problems.join(" Also, ")));
        (stored, problem)
    }
}

#[cfg(test)]
mod tests;
