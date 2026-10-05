use crate::client::BackendClient;
use crate::deployment::{self, Connection};
use crate::model::ApprovalRequest as UiApproval;
use crate::tree::Row;
use crate::ui::{Action, GenerateKind, SecretWriter};
use base64::{Engine, engine::general_purpose::STANDARD};
use nix_secrets_core::{ApprovalRequest, LeafSpec, Schema, SecretKind, SecretPath, ValueType};
use nix_secrets_core::{ProfileSnapshot, ViewProfile};
use nix_secrets_crypto::{AgeCommandProvider, EncryptedSecret, Recipient, decrypt_secret};
use nix_secrets_transport::{
    DeployEntry, Destination, ExpectedSecret, ExpectedTarget, ExpectedTask, HostIdentity,
    HostKeyStatus, PreparedDeployment, STORAGE_BOX_SSH_KEY, StorageBoxBootstrap, TargetState,
    TaskEntry,
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
    /// Rows the operator unchecked in the dialog; never sent.
    unchecked: BTreeSet<String>,
}

pub struct Controller {
    client: BackendClient,
    schema: Schema,
    provider: AgeCommandProvider,
    known_hosts: Vec<PathBuf>,
    backend_route: Option<std::sync::Arc<nix_secrets_transport::BackendRoute>>,
    connection_warnings: Vec<String>,
    active: Option<ActiveApproval>,
    host_mutations: Option<host_mutations::PendingHostMutations>,
    identity_publication: Option<host_mutations::IdentityPublication>,
    background: Option<Receiver<BackgroundUpdate>>,
    pending_rows: Option<Vec<Row>>,
    pending_profiles: Option<ProfileSnapshot>,
    approvals_ready: bool,
    background_error: Option<String>,
    /// Values the last deployment generated on its target and stored.
    last_generated: Vec<String>,
    /// Values the last deployment left out, with why.
    last_skipped: Vec<String>,
    /// What the last deployment did, counted, for the result notice.
    last_summary: Option<crate::model::DeploySummary>,
    /// Runs operator keypair generators; tests replace it.
    keypair_runner: KeypairRunner,
    phase: Option<std::sync::Arc<dyn Fn(&'static str) + Send + Sync>>,
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
    pub fn set_phase(&mut self, callback: impl Fn(&'static str) + Send + Sync + 'static) {
        self.phase = Some(std::sync::Arc::new(callback));
    }
    fn phase(&self, label: &'static str) {
        if let Some(callback) = &self.phase {
            callback(label);
        }
    }
    pub fn set_progress(&mut self, callback: impl Fn(usize, usize, bool) + Send + Sync + 'static) {
        self.provider.set_progress(callback);
    }
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
    /// Capture before an approval operation; terminal success clears active state.
    pub fn set_backend_route(
        &mut self,
        route: std::sync::Arc<nix_secrets_transport::BackendRoute>,
    ) {
        self.backend_route = Some(route);
    }

    pub fn host_mutations_before_deploy(&self) -> bool {
        self.host_mutations
            .as_ref()
            .is_some_and(|pending| pending.before_deploy)
    }

    pub fn active_approval_id(&self) -> Option<String> {
        self.active.as_ref().map(|active| active.request.id.clone())
    }

    pub fn take_generated(&mut self) -> Vec<String> {
        std::mem::take(&mut self.last_generated)
    }

    /// Values the last partial deployment skipped, for the notice.
    pub fn take_skipped(&mut self) -> Vec<String> {
        std::mem::take(&mut self.last_skipped)
    }

    /// What the last deployment did, for the result notice.
    pub fn take_summary(&mut self) -> Option<crate::model::DeploySummary> {
        self.last_summary.take()
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
            backend_route: None,
            connection_warnings: vec![],
            active: None,
            host_mutations: None,
            identity_publication: None,
            background: None,
            pending_rows: None,
            pending_profiles: None,
            approvals_ready: false,
            background_error: None,
            last_generated: Vec::new(),
            last_skipped: Vec::new(),
            last_summary: None,
            keypair_runner: crate::keypair::generate,
            phase: None,
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
            .map(|plan| {
                plan.skippable
                    .into_iter()
                    .chain(plan.host_default)
                    .collect::<Vec<_>>()
            })
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
                    ));
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
            login_key: self.login_key(&request.target).map(String::into_boxed_str),
            unchecked: BTreeSet::new(),
            cursor: 0,
            id: request.id.clone(),
            target: request.target.clone(),
            create,
            replace,
            recipient_keys: {
                // Named as the operator knows them: the schema's name, the
                // agent's title for the key and a short fingerprint.
                let agent = crate::key_names::AgentKeys::from_agent(None);
                keys.iter()
                    .map(|id| match crate::key_names::recipient_key(&self.schema, id) {
                        Some(key) => crate::key_names::describe(&self.schema, &agent, &key),
                        None => format!("unknown recipient {}", id.chars().take(12).collect::<String>()),
                    })
                    .collect()
            },
            host_key: None,
            host_mutations: vec![],
            host_mutations_before_deploy: false,
            connection_warnings: self.connection_warnings.clone(),
            host_mutation_token: None,
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

    fn deploy_active(&mut self) -> Result<Option<UiApproval>, String> {
        self.phase("Waiting for backend deployment records");
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
            plan.skippable
                .iter()
                .filter(|id| plan.reasons.get(*id) == Some(&unset::MissingKind::Optional))
                .cloned()
                .collect()
        };
        self.materialize_host_defaults(&identifiers, &plan.host_default)?;
        identifiers.retain(|identifier| {
            !skipped.contains(identifier) && !plan.host_default.contains(identifier)
        });
        // The session was opened for the request without the values that
        // wait for another host. It is never reopened: each connection costs
        // the operator an agent prompt.
        let opened = {
            let expected = &self
                .active
                .as_ref()
                .expect("active approval exists")
                .expected;
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
        // The one connection was opened for this request. It is never
        // reopened: a failure ends the deployment, and a second connection
        // would cost another agent signature.
        if self
            .active
            .as_ref()
            .expect("active approval exists")
            .prepared
            .is_none()
        {
            return Err(
                "the connection to the target is gone; request the deployment again".into(),
            );
        }
        let source_host = self
            .active
            .as_ref()
            .expect("active approval exists")
            .request
            .target
            .clone();
        // Rows the operator unchecked are not sent or generated. A derived
        // value framed on the target needs its generated source: unchecking
        // the source leaves it out too.
        let unchecked = self
            .active
            .as_ref()
            .expect("active approval exists")
            .unchecked
            .clone();
        let mut left_out = identifiers
            .iter()
            .chain(plan.shared.iter().map(|(identifier, _)| identifier))
            .filter(|identifier| unchecked.contains(*identifier))
            .cloned()
            .collect::<Vec<_>>();
        plan.generate
            .retain(|(identifier, _)| !unchecked.contains(identifier));
        plan.shared
            .retain(|(identifier, _)| !unchecked.contains(identifier));
        let generated_sources = plan
            .generate
            .iter()
            .chain(&plan.shared)
            .map(|(identifier, _)| identifier.clone())
            .collect::<BTreeSet<_>>();
        for (identifier, source) in &plan.derived_on_target {
            if !generated_sources.contains(source) && !left_out.contains(identifier) {
                left_out.push(identifier.clone());
            }
        }
        plan.derived_on_target
            .retain(|(identifier, _)| !left_out.contains(identifier));
        identifiers.retain(|identifier| !left_out.contains(identifier));
        if identifiers.is_empty() && plan.shared.is_empty() {
            return Err("every value was unchecked; nothing was sent".into());
        }
        let subset_ok = self
            .active
            .as_ref()
            .and_then(|active| active.prepared.as_ref())
            .is_some_and(|prepared| {
                prepared.state().protocol_version
                    >= nix_secrets_transport::NOT_DEPLOYED_PROTOCOL_VERSION
            });
        if !left_out.is_empty() && !subset_ok {
            return Err(format!(
                "{source_host} runs a receiver older than deployment protocol 4, which cannot leave out values after reading its state; check every row or update the host first. Nothing was sent."
            ));
        }
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
            // The preflight leaves these out when the host's protocol is
            // older or unknown; a target that says otherwise ends it here.
            return Err(format!(
                "{source_host} runs a receiver older than deployment protocol 3 and cannot generate {}; update it first. Nothing was sent.",
                plan.shared
                    .iter()
                    .map(|(id, _)| id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
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
        // Every stored value this deployment sends, and every source of a
        // derived value, decrypted in one batch: one 1Password authorization
        // for the whole deployment.
        // Public-key inventories this deployment's local keys register into
        // are decrypted in the same batch, so registering costs no second
        // authorization.
        let inventories = identifiers
            .iter()
            .filter_map(|identifier| {
                let path = SecretPath::parse(identifier).ok()?;
                match self.schema.leaf(&path).ok()? {
                    LeafSpec::Generated(task) => task.generated_secret.register_at,
                    _ => None,
                }
            })
            .filter(|inventory| entries.contains_key(inventory))
            .collect::<BTreeSet<_>>();
        let mut wanted = identifiers.clone();
        wanted.extend(
            inventories
                .iter()
                .filter(|id| !identifiers.contains(id))
                .cloned(),
        );
        let plaintexts = self.decrypt_for_deployment(
            &wanted,
            &generating,
            &derive_on_target,
            &derived,
            &entries,
        )?;
        let prefetched = inventories
            .iter()
            .filter_map(|identifier| {
                Some((
                    identifier.clone(),
                    (
                        entries.get(identifier)?.version_id.clone(),
                        plaintexts.get(identifier)?.clone(),
                    ),
                ))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for identifier in &identifiers {
            if generating.contains(identifier.as_str()) || derive_on_target.contains(identifier) {
                continue;
            }
            if let Some(source) = derived.get(identifier) {
                deploy_entries.push(self.derived_entry(
                    identifier,
                    source,
                    &entries,
                    &plaintexts,
                )?);
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
                    let record = match self
                        .identity_publication
                        .as_ref()
                        .filter(|publication| publication.path == path)
                    {
                        Some(publication) => publication.record.clone(),
                        None => self.materialize_public_default(&path, public)?,
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
            let value = plaintexts
                .get(identifier)
                .ok_or_else(|| format!("{identifier} was not decrypted"))?;
            match spec {
                LeafSpec::Stored(_) => deploy_entries.push(DeployEntry {
                    identifier: identifier.clone(),
                    version_id: STANDARD.encode(&stored.version_id),
                    contents_base64: STANDARD.encode(value.as_slice()),
                }),
                LeafSpec::Operator(_) => {
                    return Err(format!(
                        "{identifier} is operator-only and is never deployed"
                    ));
                }
                LeafSpec::Generated(_) => {
                    let contribution = crate::task::fresh_contribution()
                        .map_err(|error| format!("OS randomness failed: {error}"))?;
                    task_entries.push(TaskEntry {
                        identifier: identifier.clone(),
                        version_id: STANDARD.encode(&stored.version_id),
                        password_base64: STANDARD.encode(value.as_slice()),
                        client_contribution_base64: STANDARD.encode(&contribution[..]),
                    });
                }
            }
        }
        self.verify_identity_publication(&identifiers)?;
        let prepared = self
            .active
            .as_mut()
            .expect("active approval exists")
            .prepared
            .take()
            .expect("prepared above");
        let deploy_entries_count = deploy_entries.len() + derive_on_target.len();
        let task_entries_count = task_entries.len();
        let allowed_public_keys = task_entries
            .iter()
            .map(|entry| entry.identifier.clone())
            .collect::<BTreeSet<_>>();

        self.phase("Waiting for SSH deployment and target generators");
        let applied = deployment::deploy(
            prepared,
            deploy_entries,
            task_entries,
            generate_entries,
            derive_on_target,
        )?;
        validate_returned_public_key_scope(&allowed_public_keys, &applied.generated_public_keys)?;
        self.phase("Saving target results to the backend");
        // Store generated values first: they are the only copy outside the target.
        let stored = self.store_generated(&applied.generated_records);
        let stored = stored?;
        let mut batch = host_mutations::HostMutationBatch::default();
        self.stage_public_keys(
            &source_host,
            &applied.generated_public_keys,
            &prefetched,
            &mut batch,
        )?;
        if let Some(publication) = self.identity_publication.take() {
            if publication.was_sent(&identifiers, &applied.not_deployed) {
                batch.committed_followups = publication.followups;
            }
        }
        // Values the target left out because a prerequisite is absent there.
        skipped.extend(applied.not_deployed.keys().cloned());
        plan.missing.extend(
            applied.not_deployed.iter().map(|(identifier, reason)| {
                (identifier.clone(), format!("not deployed: {reason}"))
            }),
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
        let sent = deploy_entries_count + task_entries_count;
        self.last_summary = Some(crate::model::DeploySummary {
            target: source_host.clone(),
            sent: sent.saturating_sub(applied.not_deployed.len()),
            generated: applied.generated_records.len(),
            left_out: left_out.clone(),
            missing: skipped.clone(),
        });
        if !batch.reviews().is_empty() {
            let pending = host_mutations::PendingHostMutations {
                batch,
                before_deploy: false,
                publication: None,
                request_id: self
                    .active
                    .as_ref()
                    .expect("active approval exists")
                    .request
                    .id
                    .clone(),
                lease_id: self
                    .active
                    .as_ref()
                    .expect("active approval exists")
                    .lease_id,
                token: host_mutations::random_token()?,
                generated: stored,
                skipped,
            };
            let review = self.host_mutation_review(&pending)?;
            self.host_mutations = Some(pending);
            return Ok(Some(review));
        }
        let active = self
            .active
            .as_ref()
            .ok_or("approval lease was lost after deployment")?;
        self.client
            .renew_for(active.request.id.clone(), active.lease_id, 900_000)
            .map_err(|e| format!("approval lease was lost after deployment: {e}"))?;
        self.apply_host_mutations(batch)?;
        self.complete_host_deployment(stored, skipped)?;
        Ok(None)
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
    let mut summary = if problem.is_some() {
        format!("deployment of {target} incomplete")
    } else {
        format!("deployed {target}")
    };
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
mod host_mutations;
mod metadata;
mod operator;
mod preflight;
mod public_info;
mod registration;
mod ssh_validation;
pub(crate) mod unset;
mod writer;

mod target;
use target::{expected_target, target_has_version, target_task_has_version};

impl Controller {
    /// The key the deployment's SSH login offers, named.
    fn login_key(&self, target: &str) -> Option<String> {
        let host = self.schema.0.get(target)?;
        let keys = &host.metadata.deployment.identity_public_keys;
        if keys.is_empty() {
            return None;
        }
        let config = nix_secrets_transport::client_config(
            &"ssh".into(),
            &host.metadata.deployment.destination.clone().into(),
            host.metadata.deployment.port,
        );
        let agent = crate::key_names::AgentKeys::from_agent(config.identity_agent.as_deref());
        Some(
            keys.iter()
                .map(|key| crate::key_names::describe(&self.schema, &agent, key))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

fn validate_returned_public_key_scope(
    allowed: &BTreeSet<String>,
    returned: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    if returned
        .keys()
        .any(|identifier| !allowed.contains(identifier))
    {
        return Err(
            "target returned public-key metadata outside the approved task selection".into(),
        );
    }
    Ok(())
}
