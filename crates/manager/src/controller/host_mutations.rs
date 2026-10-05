use super::*;
use nix_secrets_core::{
    EncryptedSecret as StoredEnvelope, GeneratedPublicKey, PublicInfoRecord, SecretSpec,
};
use std::collections::BTreeMap;

/// A proposal created from one authenticated deployment, retained on the client.
/// No requester can replace its bytes or the versions displayed for consent.
#[derive(Default)]
pub(super) struct HostMutationBatch {
    pub mutations: Vec<HostMutation>,
    pub followups: BTreeMap<String, BTreeSet<String>>,
}
pub(super) struct PendingHostMutations {
    pub batch: HostMutationBatch,
    pub token: String,
    pub request_id: String,
    pub lease_id: u64,
    pub generated: Vec<String>,
    pub skipped: Vec<String>,
}
pub(super) enum HostMutation {
    Generated {
        path: SecretPath,
        previous: Option<GeneratedPublicKey>,
        proposed: GeneratedPublicKey,
    },
    Attached {
        path: SecretPath,
        version: Vec<u8>,
        previous: Option<String>,
        proposed: String,
    },
    Inventory {
        path: SecretPath,
        previous_version: Option<Vec<u8>>,
        previous_keys: Vec<String>,
        proposed: StoredEnvelope,
        proposed_keys: Vec<String>,
    },
    Identity {
        path: SecretPath,
        shared_id: String,
        previous: Option<PublicInfoRecord>,
        proposed: PublicInfoRecord,
        consumers: BTreeSet<String>,
    },
}
impl HostMutation {
    fn review(&self) -> Option<crate::model::HostMutationReview> {
        let (path, kind, previous, proposed) = match self {
            Self::Generated {
                path,
                previous: Some(previous),
                proposed,
            } => (
                path,
                "generated public key",
                fingerprints(&previous.public_key),
                fingerprints(&proposed.public_key),
            ),
            Self::Attached {
                path,
                previous: Some(previous),
                proposed,
                ..
            } => (
                path,
                "Storage Box public-key metadata",
                fingerprints(previous),
                fingerprints(proposed),
            ),
            Self::Inventory {
                path,
                previous_version: Some(_),
                previous_keys,
                proposed_keys,
                ..
            } => (
                path,
                "authorized reporter keys",
                previous_keys.clone(),
                proposed_keys.clone(),
            ),
            Self::Identity {
                path,
                previous: Some(previous),
                proposed,
                ..
            } => (
                path,
                "report receiver SSH host identity",
                known_host_fingerprints(&previous.value),
                known_host_fingerprints(&proposed.value),
            ),
            _ => return None,
        };
        Some(crate::model::HostMutationReview {
            identifier: path.to_string(),
            kind: kind.into(),
            previous,
            proposed,
        })
    }
}
impl HostMutationBatch {
    pub fn reviews(&self) -> Vec<crate::model::HostMutationReview> {
        self.mutations
            .iter()
            .filter_map(HostMutation::review)
            .collect()
    }
    pub fn followup(&mut self, path: &SecretPath) -> Result<(), String> {
        let target = path
            .components()
            .first()
            .ok_or("host mutation has no target")?
            .clone();
        self.followups
            .entry(target)
            .or_default()
            .insert(path.to_string());
        Ok(())
    }
}
fn fingerprints(value: &str) -> Vec<String> {
    ssh_key::PublicKey::from_openssh(value)
        .map(|key| {
            vec![format!(
                "{} {}",
                key.algorithm(),
                key.fingerprint(ssh_key::HashAlg::Sha256)
            )]
        })
        .unwrap_or_else(|_| vec!["invalid existing public key".into()])
}
fn known_host_fingerprints(value: &str) -> Vec<String> {
    value
        .lines()
        .map(|line| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 3 {
                return "invalid existing host identity".into();
            }
            format!(
                "{} {}",
                fields[0],
                fingerprints(&format!("{} {}", fields[1], fields[2])).join(", ")
            )
        })
        .collect()
}
pub(super) fn named_key_fingerprints(value: &str) -> Vec<String> {
    value
        .lines()
        .map(|line| {
            let (name, key) = line.split_once(' ').unwrap_or(("invalid", ""));
            format!("{name} {}", fingerprints(key).join(", "))
        })
        .collect()
}

impl Controller {
    pub(super) fn stage_host_identity(
        &mut self,
        source: &str,
        identity: &HostIdentity,
        batch: &mut HostMutationBatch,
    ) -> Result<(), String> {
        let host = self
            .schema
            .0
            .get(source)
            .ok_or("identity producer is unknown")?
            .clone();
        let Some(identifier) = &host.metadata.deployment.publish_host_identity_to else {
            return Ok(());
        };
        if identity.host != host.metadata.deployment.host
            || identity.port != host.metadata.deployment.port
            || identity.keys.is_empty()
        {
            return Err("host identity was not verified for this deployment endpoint".into());
        }
        let path = SecretPath::parse(identifier).map_err(|e| e.to_string())?;
        let spec = self
            .public_spec(&path)?
            .ok_or("host identity destination is not public info")?;
        let shared_id = spec
            .shared_public_id
            .clone()
            .ok_or("host identity destination has no shared ID")?;
        let value = render_identity(identity, &spec)?;
        let port = spec
            .expected_ssh_port
            .ok_or("host identity destination has no SSH port")?;
        let previous = self
            .client
            .get_public_info(&shared_id)
            .map_err(|e| e.to_string())?;
        if let Some(previous) = &previous {
            nix_secrets_core::schema::validate_ssh_known_hosts(
                &previous.value,
                &spec.ssh_hosts(),
                port,
            )
            .map_err(str::to_owned)?;
            if identity_keys(&previous.value, &spec, port)? == identity_keys(&value, &spec, port)? {
                return Ok(());
            }
        }
        let proposed = PublicInfoRecord {
            version_id: content_version(&value),
            value,
        };
        let mut consumers = BTreeSet::new();
        // Only already deployed reporter hosts, plus the current source. A new
        // host receives the current shared value in its own first deployment.
        for row in crate::tree::rows_with_public(&self.schema, &BTreeSet::new(), &BTreeSet::new()) {
            let Some(identifier) = row.path else {
                continue;
            };
            let Ok(path) = SecretPath::parse(&identifier) else {
                continue;
            };
            let Ok(LeafSpec::Stored(spec)) = self.schema.leaf(&path) else {
                continue;
            };
            if spec.shared_public_id.as_deref() != Some(shared_id.as_str()) {
                continue;
            }
            let Some(consumer) = path.components().first() else {
                continue;
            };
            if consumer == source || self.has_reporter_metadata(consumer)? {
                consumers.insert(path.to_string());
                batch.followup(&path)?;
            }
        }
        batch.mutations.push(HostMutation::Identity {
            path,
            shared_id,
            previous,
            proposed,
            consumers,
        });
        Ok(())
    }
    fn has_reporter_metadata(&mut self, host: &str) -> Result<bool, String> {
        for row in crate::tree::rows_with_public(&self.schema, &BTreeSet::new(), &BTreeSet::new()) {
            let Some(identifier) = row.path else {
                continue;
            };
            let Ok(path) = SecretPath::parse(&identifier) else {
                continue;
            };
            if path.components().first().map(String::as_str) != Some(host) {
                continue;
            }
            let Ok(LeafSpec::Generated(spec)) = self.schema.leaf(&path) else {
                continue;
            };
            if spec.generated_secret.secret_type
                == nix_secrets_core::GeneratedSecretType::LocalSshKey
                && spec.generated_secret.register_at.is_some()
                && self
                    .client
                    .generated_public_key(&path)
                    .map_err(|e| e.to_string())?
                    .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(super) fn apply_host_mutations(&mut self, batch: HostMutationBatch) -> Result<(), String> {
        // Check the complete review against current versions before any write.
        // CAS repeats that check under the store lock; never silently rebase.
        for mutation in &batch.mutations {
            let unchanged = match mutation {
                HostMutation::Generated { path, previous, .. } => {
                    self.client
                        .generated_public_key(path)
                        .map_err(|e| e.to_string())?
                        == *previous
                }
                HostMutation::Attached {
                    path,
                    version,
                    previous,
                    ..
                } => self
                    .client
                    .get(path)
                    .map_err(|e| e.to_string())?
                    .is_some_and(|old| old.version_id == *version && old.public_key == *previous),
                HostMutation::Inventory {
                    path,
                    previous_version,
                    ..
                } => {
                    self.client
                        .get(path)
                        .map_err(|e| e.to_string())?
                        .map(|old| old.version_id)
                        == *previous_version
                }
                HostMutation::Identity {
                    shared_id,
                    previous,
                    ..
                } => {
                    self.client
                        .get_public_info(shared_id)
                        .map_err(|e| e.to_string())?
                        == *previous
                }
            };
            if !unchanged {
                return Err(
                    "host-provided values changed after review; request new approval".into(),
                );
            }
        }
        let mut changed = BTreeSet::new();
        let result = (|| -> Result<(), String> {
            for mutation in batch.mutations {
                let path = match mutation {
                    HostMutation::Generated {
                        path,
                        previous,
                        proposed,
                    } => {
                        self.client
                            .set_generated_public_key_if_version(
                                &path,
                                proposed.clone(),
                                previous.map(|old| old.version_id),
                            )
                            .map_err(|e| e.to_string())?;
                        if self
                            .client
                            .generated_public_key(&path)
                            .map_err(|e| e.to_string())?
                            != Some(proposed)
                        {
                            return Err("generated public key failed read-back verification".into());
                        }
                        path
                    }
                    HostMutation::Attached {
                        path,
                        version,
                        previous,
                        proposed,
                    } => {
                        self.client
                            .set_public_key_if_version(
                                &path,
                                proposed.clone(),
                                version.clone(),
                                previous,
                            )
                            .map_err(|e| e.to_string())?;
                        if !self
                            .client
                            .get(&path)
                            .map_err(|e| e.to_string())?
                            .is_some_and(|old| {
                                old.version_id == version && old.public_key == Some(proposed)
                            })
                        {
                            return Err("attached public key failed read-back verification".into());
                        }
                        path
                    }
                    HostMutation::Inventory {
                        path,
                        previous_version,
                        proposed,
                        ..
                    } => {
                        self.client
                            .set_envelope_if_version(&path, proposed.clone(), previous_version)
                            .map_err(|e| e.to_string())?;
                        if !self
                            .client
                            .get(&path)
                            .map_err(|e| e.to_string())?
                            .is_some_and(|old| {
                                old.version_id == proposed.version_id
                                    && old.age_ciphertext == proposed.age_ciphertext
                            })
                        {
                            return Err(
                                "registered public key failed read-back verification".into()
                            );
                        }
                        path
                    }
                    HostMutation::Identity {
                        path,
                        shared_id,
                        previous,
                        proposed,
                        consumers,
                    } => {
                        self.client
                            .set_public_info_if_version(
                                &path,
                                proposed.clone(),
                                previous.map(|old| old.version_id),
                            )
                            .map_err(|e| e.to_string())?;
                        if self
                            .client
                            .get_public_info(&shared_id)
                            .map_err(|e| e.to_string())?
                            != Some(proposed)
                        {
                            return Err("host identity failed read-back verification".into());
                        }
                        // Each shared consumer needs the same changed value.
                        changed.extend(consumers);
                        path
                    }
                };
                changed.insert(path.to_string());
            }
            Ok(())
        })();
        // Preserve consent requests for writes already completed if a later
        // CAS fails. No consumer connection or deployment occurs here.
        for (target, identifiers) in batch.followups {
            let secrets = identifiers
                .into_iter()
                .filter(|id| changed.contains(id))
                .collect::<Vec<_>>();
            if secrets.is_empty() {
                continue;
            }
            self.client
                .submit_approval(ApprovalRequest {
                    id: format!("pubkey-{}", random_token()?),
                    target,
                    secrets,
                    allow_partial: false,
                })
                .map_err(|e| e.to_string())?;
        }
        result
    }
    pub(super) fn host_mutation_review(
        &mut self,
        pending: &PendingHostMutations,
    ) -> Result<UiApproval, String> {
        let request = self
            .active
            .as_ref()
            .ok_or("no claimed approval request")?
            .request
            .clone();
        let set = self.plan_set(&request.secrets)?;
        let mut review = self.approval_details(&request, None, &set)?;
        review.host_mutations = pending.batch.reviews();
        review.host_mutation_token = Some(pending.token.clone());
        Ok(review)
    }
    pub(super) fn complete_host_deployment(
        &mut self,
        generated: Vec<String>,
        skipped: Vec<String>,
    ) -> Result<(), String> {
        let active = self.active.take().ok_or("no claimed approval request")?;
        let summary = deployment_summary(&active.request.target, &generated, &skipped, None);
        self.client
            .resolve(active.request.id, active.lease_id, true, Some(summary))
            .map_err(|e| e.to_string())?;
        self.last_generated = generated;
        self.last_skipped = skipped;
        Ok(())
    }
    pub(super) fn approve_host_mutations_inner(
        &mut self,
        accepted: bool,
        token: &str,
    ) -> Result<Option<UiApproval>, String> {
        let active = self.active.as_ref().ok_or("no claimed approval request")?;
        let pending = self
            .host_mutations
            .as_ref()
            .ok_or("no host-provided changes awaiting approval")?;
        if pending.request_id != active.request.id || pending.lease_id != active.lease_id {
            return Err("host-provided change approval belongs to another request or lease".into());
        }
        if token != pending.token {
            return Err("host-provided change approval does not match the displayed batch".into());
        }
        // Renew checks this frontend still owns the live lease. If expired,
        // disconnected or reassigned, no staged write is attempted.
        if let Err(error) =
            self.client
                .renew_for(active.request.id.clone(), active.lease_id, 900_000)
        {
            self.host_mutations = None;
            self.active = None;
            return Err(format!(
                "host-provided change approval lease was lost: {error}"
            ));
        }
        let pending = self.host_mutations.take().expect("pending checked");
        if !accepted {
            let active = self.active.take().expect("active checked");
            self.client.resolve(active.request.id, active.lease_id, false, Some("target deployment completed; host-provided changes rejected, existing values kept".into())).map_err(|e| e.to_string())?;
            return Ok(None);
        }
        if let Err(error) = self.apply_host_mutations(pending.batch) {
            if let Some(active) = self.active.take() {
                let _ = self.client.resolve(
                    active.request.id,
                    active.lease_id,
                    false,
                    Some(error.clone()),
                );
            }
            return Err(error);
        }
        self.complete_host_deployment(pending.generated, pending.skipped)?;
        Ok(None)
    }
}
fn content_version(value: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub(super) fn random_token() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "cannot create host mutation review token")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn render_identity(identity: &HostIdentity, spec: &SecretSpec) -> Result<String, String> {
    let port = spec
        .expected_ssh_port
        .ok_or("host identity destination has no SSH port")?;
    let mut lines = BTreeSet::new();
    for host in spec.ssh_hosts() {
        for key in &identity.keys {
            let name = if port == 22 {
                host.to_owned()
            } else {
                format!("[{host}]:{port}")
            };
            lines.insert(format!("{name} {} {}", key.algorithm, key.encoded));
        }
    }
    let value = lines
        .into_iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    nix_secrets_core::schema::validate_ssh_known_hosts(&value, &spec.ssh_hosts(), port)
        .map_err(str::to_owned)?;
    Ok(value)
}
fn identity_keys(
    value: &str,
    spec: &SecretSpec,
    port: u16,
) -> Result<BTreeSet<(String, String)>, String> {
    let mut keys = BTreeSet::new();
    for host in spec.ssh_hosts() {
        for key in nix_secrets_core::schema::known_hosts_keys(value, &spec.ssh_hosts(), port, host)
            .map_err(str::to_owned)?
        {
            keys.insert((host.to_owned(), key));
        }
    }
    Ok(keys)
}
