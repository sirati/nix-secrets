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
}

impl UnsetPlan {
    /// Also refuses a derived value whose source is unset: its source must be
    /// set, or deployed to its own host first when that host generates it.
    pub fn refusal(&self) -> Option<String> {
        (!self.missing.is_empty()).then(|| {
            format!(
                "Missing values that must be entered: {}. Nothing was generated or written.",
                self.missing
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
/// task whose operator input is unset is always missing. Public information
/// and target-local keys need no stored value.
pub(crate) fn plan_unset(
    schema: &Schema,
    identifiers: &[String],
    set: &BTreeSet<String>,
) -> Result<UnsetPlan, String> {
    let mut plan = UnsetPlan::default();
    let mut waiting = Vec::new();
    for identifier in identifiers {
        let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
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
                    plan.missing
                        .push((identifier.clone(), "task input".to_owned()));
                }
                continue;
            }
        };
        if matches!(spec.kind, SecretKind::PublicInfo) {
            continue;
        }
        match deployment_generator(&spec) {
            Ok(generator) => plan.generate.push((identifier.clone(), generator.label())),
            Err(reason) => plan
                .missing
                .push((identifier.clone(), reason.reason().to_owned())),
        }
    }
    // An unset source generated in this same request is on the same host
    // (a request names one target), so that target frames the derived value
    // from what it generates, and both land in one atomic generation.
    for (identifier, source) in waiting {
        if plan
            .generate
            .iter()
            .any(|(generated, _)| generated == &source)
        {
            plan.derived_on_target.push((identifier, source));
        } else {
            let reason = source_first(schema, &source);
            plan.missing.push((identifier, reason));
        }
    }
    Ok(plan)
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

pub(crate) fn generate_entries(plan: &UnsetPlan) -> Result<Vec<GenerateEntry>, String> {
    plan.generate
        .iter()
        .map(|(identifier, _)| {
            let contribution = crate::task::fresh_contribution()
                .map_err(|error| format!("OS randomness failed: {error}"))?;
            Ok(GenerateEntry {
                identifier: identifier.clone(),
                client_contribution_base64: STANDARD.encode(&contribution[..]),
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
    /// Decrypts a derived value's source and frames it. The version names the
    /// source version and the framing, so the target replaces the derived
    /// value exactly when either changes.
    pub(super) fn derived_entry(
        &self,
        identifier: &str,
        source: &str,
        entries: &BTreeMap<String, nix_secrets_core::EncryptedSecret>,
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
        let record = EncryptedSecret {
            format_version: stored.format_version,
            version_id: stored.version_id.clone(),
            recipient_ids: stored.recipient_ids.clone(),
            age_ciphertext: stored.age_ciphertext.clone(),
        };
        let value =
            decrypt_secret(source, &record, &self.provider).map_err(|error| error.to_string())?;
        let framed = derived.frame(&value);
        Ok(DeployEntry {
            identifier: identifier.to_owned(),
            version_id: derived.version(&stored.version_id),
            contents_base64: STANDARD.encode(framed.as_slice()),
        })
    }

    /// Stores target-generated records only where the value is still unset.
    /// A value entered meanwhile is kept; the next deployment then replaces
    /// the target's copy with it.
    pub(super) fn store_generated(
        &mut self,
        records: &BTreeMap<String, GeneratedRecord>,
    ) -> Result<Vec<String>, String> {
        let mut envelopes = Vec::with_capacity(records.len());
        for (identifier, record) in records {
            envelopes.push((
                identifier.clone(),
                record_envelope(&self.schema, identifier, record)?,
            ));
        }
        let mut stored = Vec::new();
        let mut conflicts = Vec::new();
        let mut failures = Vec::new();
        for (identifier, envelope) in envelopes {
            let path = SecretPath::parse(&identifier).map_err(|error| error.to_string())?;
            match self.client.set_envelope_if_version(&path, envelope, None) {
                Ok(()) => stored.push(identifier),
                Err(error) if error.to_string().contains("version changed") => {
                    conflicts.push(identifier)
                }
                Err(error) => failures.push(format!("{identifier}: {error}")),
            }
        }
        let mut problems = Vec::new();
        if !failures.is_empty() {
            problems.push(format!(
                "storing failed for {}. Deploy again: the target returns the installed values.",
                failures.join("; ")
            ));
        }
        if !conflicts.is_empty() {
            problems.push(format!(
                "these were entered in the store meanwhile and kept: {}. \
                 Deploy again to install the stored values.",
                conflicts.join(", ")
            ));
        }
        if problems.is_empty() {
            Ok(stored)
        } else {
            Err(format!("Deployed, but {}", problems.join(" Also, ")))
        }
    }
}

#[cfg(test)]
mod tests;
