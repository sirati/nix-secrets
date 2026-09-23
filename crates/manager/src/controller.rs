use crate::client::BackendClient;
use crate::deployment::{self, Connection};
use crate::model::ApprovalRequest as UiApproval;
use crate::tree::Row;
use crate::ui::{Action, GenerateKind, SecretWriter};
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::{ApprovalRequest, LeafSpec, Schema, SecretKind, SecretPath, ValueType};
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
        let public = self
            .client
            .list_public_info()?
            .into_keys()
            .collect::<BTreeSet<_>>();
        Ok(crate::tree::rows_with_public(&self.schema, &set, &public))
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
                    if !matches!(spec.kind, SecretKind::PublicInfo) {
                        keys.extend(spec.recipient_ids);
                    }
                    if let Some(state) = state {
                        if target_has_version(state, identifier)? {
                            replace.push(identifier.clone());
                        } else {
                            create.push(identifier.clone());
                        }
                    }
                }
                LeafSpec::Generated(spec) => {
                    if spec.generated_secret.secret_type
                        != nix_secrets_core::GeneratedSecretType::LocalSshKey
                    {
                        keys.extend(spec.recipient_ids);
                    }
                    let output_is_set = state
                        .map(|state| target_task_has_version(state, identifier))
                        .transpose()?;
                    tasks.push(crate::model::TaskApproval {
                        identifier: identifier.clone(),
                        input_is_set: spec.generated_secret.secret_type
                            == nix_secrets_core::GeneratedSecretType::LocalSshKey
                            || set.contains(identifier),
                        output_is_set,
                        requires_input: spec.generated_secret.secret_type
                            != nix_secrets_core::GeneratedSecretType::LocalSshKey,
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
            let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
            let spec = self.schema.leaf(&path).map_err(|error| error.to_string())?;
            if let LeafSpec::Stored(public) = &spec {
                if matches!(public.kind, SecretKind::PublicInfo) {
                    let id = public
                        .shared_public_id
                        .as_deref()
                        .ok_or("public info has no shared ID")?;
                    let record = self
                        .client
                        .get_public_info(id)
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| format!("required public info is unset: {identifier}"))?;
                    nix_secrets_core::schema::validate_ssh_known_hosts(
                        &record.value,
                        public
                            .expected_ssh_host
                            .as_deref()
                            .ok_or("missing expected SSH host")?,
                        public
                            .expected_ssh_port
                            .ok_or("missing expected SSH port")?,
                    )
                    .map_err(str::to_owned)?;
                    deploy_entries.push(DeployEntry {
                        identifier: identifier.clone(),
                        version_id: record.version_id,
                        contents_base64: STANDARD.encode(record.value.as_bytes()),
                    });
                    continue;
                }
            }
            if matches!(&spec, LeafSpec::Generated(task) if task.generated_secret.secret_type == nix_secrets_core::GeneratedSecretType::LocalSshKey)
            {
                let contribution = crate::task::fresh_contribution()
                    .map_err(|error| format!("OS randomness failed: {error}"))?;
                task_entries.push(TaskEntry {
                    identifier: identifier.clone(),
                    version_id: "local-generated-v1".into(),
                    password_base64: String::new(),
                    client_contribution_base64: STANDARD.encode(&contribution[..]),
                });
                continue;
            }
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
            match spec {
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

mod generate;
mod metadata;
mod public_info;
mod registration;
mod ssh_validation;
mod writer;

mod target;
use target::{expected_target, target_has_version, target_task_has_version};
