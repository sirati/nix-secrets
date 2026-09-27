use crate::client::BackendClient;
use crate::deployment::{self, Connection};
use crate::model::ApprovalRequest as UiApproval;
use crate::tree::Row;
use crate::ui::{Action, GenerateKind, SecretWriter};
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::{ApprovalRequest, LeafSpec, Schema, SecretKind, SecretPath, ValueType};
use nix_secrets_core::{ProfileSnapshot, ViewProfile};
use nix_secrets_crypto::{decrypt_secret, AgeCommandProvider, EncryptedSecret, Recipient};
use nix_secrets_transport::{
    DeployEntry, Destination, ExpectedSecret, ExpectedTarget, ExpectedTask, HostIdentity,
    HostKeyStatus, PreparedDeployment, StorageBoxBootstrap, TargetState, TaskEntry,
    STORAGE_BOX_SSH_KEY,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
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
    /// Why the last approval failed, reported if the operator then rejects.
    last_error: Option<String>,
}

pub struct Controller {
    client: BackendClient,
    schema: Schema,
    provider: AgeCommandProvider,
    known_hosts: Vec<PathBuf>,
    active: Option<ActiveApproval>,
    background: Option<Receiver<BackgroundUpdate>>,
    pending_rows: Option<Vec<Row>>,
    pending_profiles: Option<ProfileSnapshot>,
    approvals_ready: bool,
    background_error: Option<String>,
    /// Values the last deployment generated on its target and stored.
    last_generated: Vec<String>,
    /// Values the last deployment left out, with why.
    last_skipped: Vec<String>,
    /// Runs operator keypair generators; tests replace it.
    keypair_runner: KeypairRunner,
}

pub type KeypairRunner =
    fn(&nix_secrets_core::KeypairGenerator) -> Result<crate::keypair::Keypair, String>;

enum BackgroundUpdate {
    Rows(Vec<Row>),
    Profiles(ProfileSnapshot),
    ApprovalPending,
    Error(String),
}

impl Controller {
    /// The schema and decryption provider, for the secret-request channel.
    pub fn schema_and_provider(&self) -> (Schema, AgeCommandProvider) {
        (self.schema.clone(), self.provider.clone())
    }

    pub fn uses_one_password(&self) -> bool {
        self.provider.uses_one_password()
    }

    /// Replaces the program that runs keypair generators, for tests.
    pub fn with_keypair_runner(mut self, runner: KeypairRunner) -> Self {
        self.keypair_runner = runner;
        self
    }

    /// Values the last deployment generated on its target, for the notice.
    pub fn take_generated(&mut self) -> Vec<String> {
        std::mem::take(&mut self.last_generated)
    }

    /// Values the last partial deployment skipped, for the notice.
    pub fn take_skipped(&mut self) -> Vec<String> {
        std::mem::take(&mut self.last_skipped)
    }
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
            background: None,
            pending_rows: None,
            pending_profiles: None,
            approvals_ready: false,
            background_error: None,
            last_generated: Vec::new(),
            last_skipped: Vec::new(),
            keypair_runner: crate::keypair::generate,
        })
    }

    /// Keep idle backend traffic off the terminal's input thread. The worker
    /// has its own verified socket; only the UI session may claim approvals.
    pub fn start_background_refresh(&mut self, socket: PathBuf) {
        let schema = self.schema.clone();
        let (sender, receiver) = mpsc::channel();
        self.background = Some(receiver);
        std::thread::spawn(move || {
            if let Err(error) = background::listen(socket, schema, &sender) {
                let _ = sender.send(BackgroundUpdate::Error(error.to_string()));
            }
        });
    }

    fn drain_background(&mut self) {
        let Some(receiver) = &self.background else {
            return;
        };
        while let Ok(update) = receiver.try_recv() {
            match update {
                BackgroundUpdate::Rows(rows) => self.pending_rows = Some(rows),
                BackgroundUpdate::Profiles(snapshot) => self.pending_profiles = Some(snapshot),
                BackgroundUpdate::ApprovalPending => self.approvals_ready = true,
                BackgroundUpdate::Error(error) => self.background_error = Some(error),
            }
        }
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
        // Values not in the target selection: missing ones and public
        // information the host installs its own default for.
        let skippable = unset::plan_unset(&self.schema, &request.secrets, set)
            .map(|plan| plan.skippable.into_iter().chain(plan.host_default).collect::<Vec<_>>())
            .unwrap_or_default();
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
                    // Not selected on the target: it waits for another host.
                    if let Some(state) = state.filter(|_| !skippable.contains(identifier)) {
                        if target_has_version(state, identifier)? {
                            replace.push(identifier.clone());
                        } else {
                            create.push(identifier.clone());
                        }
                    }
                }
                LeafSpec::Operator(_) => {
                    return Err(format!(
                        "{identifier} is operator-only and is never deployed"
                    ))
                }
                LeafSpec::Generated(spec) => {
                    if spec.generated_secret.secret_type
                        != nix_secrets_core::GeneratedSecretType::LocalSshKey
                    {
                        keys.extend(spec.recipient_ids);
                    }
                    let output_is_set = state
                        .filter(|_| !skippable.contains(identifier))
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
        let plan = unset::plan_unset(&self.schema, &request.secrets, set)?;
        Ok(UiApproval {
            skippable: plan.skippable.clone(),
            missing_kinds: plan
                .reasons
                .iter()
                .map(|(identifier, kind)| (identifier.clone(), kind.label().to_owned()))
                .collect(),
            host_default: plan.host_default.clone(),
            // Missing values never block: everything else is deployed.
            allow_partial: true,
            id: request.id.clone(),
            target: request.target.clone(),
            create,
            replace,
            recipient_keys: keys.into_iter().collect(),
            host_key: None,
            tasks,
            generate: plan
                .generate
                .into_iter()
                .chain(plan.shared.into_iter().map(|(identifier, label)| {
                    let host = identifier.split('.').next().unwrap_or("").to_owned();
                    (
                        identifier,
                        format!("{label}; shared with {host}, generated and encrypted on {} and stored as ciphertext", request.target),
                    )
                }))
                .collect(),
            missing: plan.missing,
            derived: plan
                .derived
                .into_iter()
                .chain(plan.derived_on_target)
                .collect(),
        })
    }

    fn deploy_active(&mut self) -> Result<(), String> {
        let active = self.active.as_ref().ok_or("no claimed approval request")?;
        let mut identifiers = active.request.secrets.clone();
        // Missing values never block: two hosts that need each other's
        // values would otherwise never deploy. They are listed instead.
        let allow_partial = true;
        let set = self.plan_set(&identifiers)?;
        let entries = self.client.list().map_err(|error| error.to_string())?;
        // Refuse before connecting, decrypting, generating, or writing.
        let mut plan = unset::plan_unset(&self.schema, &identifiers, &set)?;
        if let Some(refusal) = plan.refusal_for(allow_partial) {
            return Err(refusal);
        }
        // A partial deployment leaves the values that wait for another host
        // out of the target selection, so the target keeps waiting for them.
        let mut skipped = if allow_partial {
            plan.skippable.clone()
        } else {
            Vec::new()
        };
        identifiers.retain(|identifier| {
            !skipped.contains(identifier) && !plan.host_default.contains(identifier)
        });
        // The session was opened for the request without the values that
        // wait for another host. It is never reopened: each connection costs
        // the operator an agent prompt.
        let opened = {
            let expected = &self.active.as_ref().expect("active approval exists").expected;
            expected
                .secrets
                .iter()
                .map(|secret| &secret.identifier)
                .chain(expected.tasks.iter().map(|task| &task.identifier))
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        if opened != identifiers.iter().cloned().collect::<BTreeSet<_>>() {
            return Err(
                "values changed in the store since the target was read; request the deployment again"
                    .into(),
            );
        }
        if self
            .active
            .as_ref()
            .expect("active approval exists")
            .prepared
            .is_none()
        {
            self.prepare_active()?;
        }
        let source_host = self
            .active
            .as_ref()
            .expect("active approval exists")
            .request
            .target
            .clone();
        let generating = plan
            .generate
            .iter()
            .map(|(identifier, _)| identifier.as_str())
            .collect::<BTreeSet<_>>();
        let old_target = self
            .active
            .as_ref()
            .and_then(|active| active.prepared.as_ref())
            .is_some_and(|prepared| !prepared.supports_shared_sources());
        if !plan.shared.is_empty() && old_target {
            // The target cannot generate a shared value yet. Its derived values
            // wait, and the rest deploys over a narrower selection: one more
            // connection, only against such an old target.
            let shared = std::mem::take(&mut plan.shared);
            let waiting = plan
                .derived_on_target
                .iter()
                .filter(|(_, source)| shared.iter().any(|(id, _)| id == source))
                .map(|(identifier, _)| identifier.clone())
                .collect::<Vec<_>>();
            plan.derived_on_target
                .retain(|(identifier, _)| !waiting.contains(identifier));
            identifiers.retain(|identifier| !waiting.contains(identifier));
            skipped.extend(waiting);
            let active = self.active.as_mut().expect("active approval exists");
            let mut narrowed = active.request.clone();
            narrowed.secrets = identifiers.clone();
            active.expected = expected_target(&self.schema, &narrowed)?;
            active.prepared = None;
            self.prepare_active()?;
        }
        let generate_entries = unset::generate_entries(&self.schema, &plan)?;
        let derive_on_target = plan
            .derived_on_target
            .iter()
            .map(|(identifier, _)| identifier.clone())
            .collect::<Vec<_>>();
        let mut deploy_entries = Vec::new();
        let mut task_entries = Vec::new();
        let derived = plan
            .derived
            .iter()
            .cloned()
            .collect::<std::collections::BTreeMap<_, _>>();
        for identifier in &identifiers {
            if generating.contains(identifier.as_str()) || derive_on_target.contains(identifier) {
                continue;
            }
            if let Some(source) = derived.get(identifier) {
                deploy_entries.push(self.derived_entry(identifier, source, &entries)?);
                continue;
            }
            let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
            let spec = self.schema.leaf(&path).map_err(|error| error.to_string())?;
            if let LeafSpec::Stored(public) = &spec {
                if matches!(public.kind, SecretKind::PublicInfo) {
                    let id = public
                        .shared_public_id
                        .as_deref()
                        .ok_or("public info has no shared ID")?;
                    // The stored value, else the leaf's own defaultValue.
                    let record = match self
                        .client
                        .get_public_info(id)
                        .map_err(|error| error.to_string())?
                    {
                        Some(record) => record,
                        None => public_info::default_record(public)
                            .ok_or_else(|| format!("required public info is unset: {identifier}"))?,
                    };
                    nix_secrets_core::schema::validate_ssh_known_hosts(
                        &record.value,
                        &public.ssh_hosts(),
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
                .ok_or_else(|| format!("required secret became unset: {identifier}"))?;
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
                LeafSpec::Operator(_) => {
                    return Err(format!(
                        "{identifier} is operator-only and is never deployed"
                    ))
                }
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
        let applied = deployment::deploy(
            prepared,
            deploy_entries,
            task_entries,
            generate_entries,
            derive_on_target,
        )?;
        // Store generated values first: they are the only copy outside the target.
        let stored = self.store_generated(&applied.generated_records);
        let registered = self.register_public_keys(&source_host, &applied.generated_public_keys);
        let active = self.active.take().expect("approval remains active");
        // Values the target left out because a prerequisite is absent there.
        skipped.extend(applied.not_deployed.keys().cloned());
        plan.missing.extend(
            applied
                .not_deployed
                .iter()
                .map(|(identifier, reason)| (identifier.clone(), format!("not deployed: {reason}"))),
        );
        let skipped = skipped
            .iter()
            .map(|identifier| {
                let reason = plan
                    .missing
                    .iter()
                    .find(|(id, _)| id == identifier)
                    .map(|(_, reason)| reason.as_str())
                    .unwrap_or("its shared source needs a newer target");
                format!("{identifier} ({reason})")
            })
            .collect::<Vec<_>>();
        let summary = deployment_summary(
            &source_host,
            stored.as_ref().map(Vec::as_slice).unwrap_or(&[]),
            &skipped,
            stored.as_ref().err().or(registered.as_ref().err()),
        );
        self.client
            .resolve(active.request.id, active.lease_id, true, Some(summary))
            .map_err(|error| error.to_string())?;
        let stored = stored?;
        registered?;
        self.last_generated = stored;
        self.last_skipped = skipped;
        Ok(())
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

/// What a finished deployment did, for the requester of the approval.
fn deployment_summary(
    target: &str,
    generated: &[String],
    skipped: &[String],
    problem: Option<&String>,
) -> String {
    let mut summary = format!("deployed {target}");
    if !generated.is_empty() {
        summary.push_str(&format!("; generated and stored: {}", generated.join(", ")));
    }
    if !skipped.is_empty() {
        summary.push_str(&format!(
            "; not deployed yet, {target} waits for: {}",
            skipped.join(", ")
        ));
    }
    if let Some(problem) = problem {
        summary.push_str(&format!("; {problem}"));
    }
    summary
}

mod background;
mod generate;
mod metadata;
mod operator;
mod public_info;
mod registration;
mod ssh_validation;
pub(crate) mod unset;
mod writer;

mod target;
use target::{expected_target, target_has_version, target_task_has_version};
