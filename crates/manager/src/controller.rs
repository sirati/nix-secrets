use crate::client::BackendClient;
use crate::deployment::{self, Connection};
use crate::model::ApprovalRequest as UiApproval;
use crate::tree::Row;
use crate::ui::{Action, SecretWriter};
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::{ApprovalRequest, LeafSpec, Schema, SecretPath};
use nix_secrets_crypto::{decrypt_secret, AgeCommandProvider, EncryptedSecret, Recipient};
use nix_secrets_transport::{
    DeployEntry, Destination, ExpectedSecret, ExpectedTarget, ExpectedTask, HostIdentity,
    HostKeyStatus, PreparedDeployment, StorageBoxBootstrap, TargetState, TaskEntry,
    STORAGE_BOX_SSH_KEY,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

struct ActiveApproval {
    request: ApprovalRequest,
    lease_id: u64,
    connection: Connection,
    expected: ExpectedTarget,
    identity: HostIdentity,
    prepared: Option<PreparedDeployment>,
    target_approved: bool,
    renewed_at: Instant,
}

pub struct Controller {
    client: BackendClient,
    schema: Schema,
    provider: AgeCommandProvider,
    known_hosts: Vec<PathBuf>,
    active: Option<ActiveApproval>,
}

impl Controller {
    pub fn new(
        mut client: BackendClient,
        schema: Schema,
        provider: AgeCommandProvider,
        known_hosts: Vec<PathBuf>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        client.register_frontend()?;
        Ok(Self {
            client,
            schema,
            provider,
            known_hosts,
            active: None,
        })
    }

    pub fn rows(&mut self) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
        let set = self.client.list()?.into_keys().collect::<BTreeSet<_>>();
        Ok(crate::tree::rows(&self.schema, &set))
    }

    fn approval_details(
        &self,
        request: &ApprovalRequest,
        state: Option<&TargetState>,
        set: &BTreeSet<String>,
    ) -> Result<UiApproval, String> {
        let mut create = Vec::new();
        let mut replace = Vec::new();
        let mut tasks = Vec::new();
        let mut keys = BTreeSet::new();
        for identifier in &request.secrets {
            let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
            if path.components().first().map(String::as_str) != Some(request.target.as_str()) {
                return Err(format!(
                    "{identifier} does not belong to target {}",
                    request.target
                ));
            }
            let spec = self.schema.leaf(&path).map_err(|error| error.to_string())?;
            match spec {
                LeafSpec::Stored(spec) => {
                    keys.extend(spec.recipient_ids);
                    if let Some(state) = state {
                        if target_has_version(state, identifier)? {
                            replace.push(identifier.clone());
                        } else {
                            create.push(identifier.clone());
                        }
                    }
                }
                LeafSpec::Generated(spec) => {
                    keys.extend(spec.recipient_ids);
                    let output_is_set = state
                        .map(|state| target_task_has_version(state, identifier))
                        .transpose()?;
                    tasks.push(crate::model::TaskApproval {
                        identifier: identifier.clone(),
                        input_is_set: set.contains(identifier),
                        output_is_set,
                    });
                }
            }
        }
        Ok(UiApproval {
            id: request.id.clone(),
            target: request.target.clone(),
            create,
            replace,
            recipient_keys: keys.into_iter().collect(),
            host_key: None,
            tasks,
        })
    }

    fn deploy_active(&mut self) -> Result<(), String> {
        if self
            .active
            .as_ref()
            .ok_or("no claimed approval request")?
            .prepared
            .is_none()
        {
            self.prepare_active()?;
        }
        let active = self.active.as_ref().expect("active approval exists");
        let source_host = active.request.target.clone();
        let entries = self.client.list().map_err(|error| error.to_string())?;
        let identifiers = active.request.secrets.clone();
        let mut deploy_entries = Vec::new();
        let mut task_entries = Vec::new();
        for identifier in &identifiers {
            let stored = entries
                .get(identifier)
                .ok_or_else(|| format!("required secret is unset: {identifier}"))?;
            let record = EncryptedSecret {
                format_version: stored.format_version,
                version_id: stored.version_id.clone(),
                recipient_ids: stored.recipient_ids.clone(),
                age_ciphertext: stored.age_ciphertext.clone(),
            };
            let value = decrypt_secret(identifier, &record, &self.provider)
                .map_err(|error| error.to_string())?;
            let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
            match self.schema.leaf(&path).map_err(|error| error.to_string())? {
                LeafSpec::Stored(_) => deploy_entries.push(DeployEntry {
                    identifier: identifier.clone(),
                    version_id: STANDARD.encode(&stored.version_id),
                    contents_base64: STANDARD.encode(&value),
                }),
                LeafSpec::Generated(_) => {
                    let contribution = crate::task::fresh_contribution()
                        .map_err(|error| format!("OS randomness failed: {error}"))?;
                    task_entries.push(TaskEntry {
                        identifier: identifier.clone(),
                        version_id: STANDARD.encode(&stored.version_id),
                        password_base64: STANDARD.encode(&value),
                        client_contribution_base64: STANDARD.encode(&contribution[..]),
                    });
                }
            }
        }
        let prepared = self
            .active
            .as_mut()
            .expect("active approval exists")
            .prepared
            .take()
            .expect("prepared above");
        let public_keys = deployment::deploy(prepared, deploy_entries, task_entries)?;
        self.register_public_keys(&source_host, &public_keys)?;
        let active = self.active.take().expect("approval remains active");
        self.client
            .resolve(active.request.id, active.lease_id, true)
            .map_err(|error| error.to_string())
    }

    fn prepare_active(&mut self) -> Result<(), String> {
        let active = self.active.as_ref().ok_or("no claimed approval request")?;
        let prepared = deployment::prepare(&active.connection, &active.expected, &active.identity)?;
        self.active
            .as_mut()
            .expect("active approval exists")
            .prepared = Some(prepared);
        Ok(())
    }
}

mod registration;
mod writer;

fn expected_target(schema: &Schema, request: &ApprovalRequest) -> Result<ExpectedTarget, String> {
    let mut secrets = Vec::new();
    let mut tasks = Vec::new();
    for identifier in &request.secrets {
        let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
        match schema.leaf(&path).map_err(|error| error.to_string())? {
            LeafSpec::Stored(spec) => secrets.push(ExpectedSecret {
                identifier: identifier.clone(),
                recipient_ids: spec.recipient_ids,
                destination: destination(spec.destination, spec.consumer_units),
            }),
            LeafSpec::Generated(spec) => tasks.push(ExpectedTask {
                identifier: identifier.clone(),
                task_type: match spec.generated_secret.secret_type {
                    nix_secrets_core::GeneratedSecretType::StorageBoxSshKey => STORAGE_BOX_SSH_KEY,
                    nix_secrets_core::GeneratedSecretType::LocalSshKey => {
                        nix_secrets_transport::LOCAL_SSH_KEY
                    }
                }
                .into(),
                recipient_ids: spec.recipient_ids,
                output: destination(spec.generated_secret.output, spec.consumer_units),
                bootstrap: spec
                    .generated_secret
                    .bootstrap
                    .map(|bootstrap| StorageBoxBootstrap {
                        host: bootstrap.host,
                        port: bootstrap.port,
                        user: bootstrap.user,
                        host_public_keys: bootstrap.host_public_keys,
                    }),
            }),
        }
    }
    Ok(ExpectedTarget {
        hostname: request.target.clone(),
        secrets,
        tasks,
    })
}

fn destination(value: nix_secrets_core::Destination, consumer_units: Vec<String>) -> Destination {
    Destination {
        path: value.path,
        category: value.category,
        owner: value.owner,
        group: value.group,
        mode: value.mode,
        consumer_units,
    }
}

fn target_has_version(state: &TargetState, identifier: &str) -> Result<bool, String> {
    state
        .secrets
        .iter()
        .find(|secret| secret.identifier == identifier)
        .map(|secret| secret.current_version_id.is_some())
        .ok_or_else(|| format!("target omitted {identifier}"))
}

fn target_task_has_version(state: &TargetState, identifier: &str) -> Result<bool, String> {
    state
        .tasks
        .iter()
        .find(|task| task.identifier == identifier)
        .map(|task| task.current_version_id.is_some())
        .ok_or_else(|| format!("target omitted task {identifier}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_secrets_transport::TargetSecret;

    #[test]
    fn target_state_is_authoritative_for_create_and_replace() {
        let destination = Destination {
            path: "/persistent/secrets/s/service/a".into(),
            category: "service".into(),
            owner: "s".into(),
            group: "s".into(),
            mode: "0400".into(),
            consumer_units: vec![],
        };
        let secret = |identifier: &str, version: Option<&str>| TargetSecret {
            identifier: identifier.into(),
            recipient_ids: vec!["key".into()],
            destination: destination.clone(),
            current_version_id: version.map(str::to_owned),
        };
        let state = TargetState {
            protocol_version: 1,
            hostname: "host".into(),
            secrets: vec![
                secret("host.services.s.new", None),
                secret("host.services.s.old", Some("version")),
            ],
            tasks: vec![],
        };
        assert!(!target_has_version(&state, "host.services.s.new").unwrap());
        assert!(target_has_version(&state, "host.services.s.old").unwrap());
    }
}
