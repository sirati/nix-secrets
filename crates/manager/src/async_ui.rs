use crate::controller::Controller;
use crate::model::ApprovalRequest;
use crate::tree::Row;
use crate::ui::{Action, Completion, GenerateKind, ProcedureEvent, SecretWriter, OPERATION_QUEUED};
use nix_secrets_core::{ProfileSnapshot, ViewProfile};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;
use zeroize::Zeroizing;

enum Command {
    Write {
        path: String,
        value: Zeroizing<Vec<u8>>,
    },
    Delete(String),
    Reveal(String),
    CopyPublic(String),
    CopyValue(Zeroizing<Vec<u8>>),
    Generate {
        path: String,
        kind: GenerateKind,
        replacing: bool,
    },
    BulkGenerate {
        paths: Vec<String>,
        kind: GenerateKind,
    },
    GenerateKeypair(String),
    Approval(bool),
    ApprovalWith(bool, std::collections::BTreeSet<String>),
    HostMutations(bool, String),
    RequestDeployment(String),
    SaveProfile {
        name: String,
        profile: ViewProfile,
        revision: u64,
    },
    CommitSummary,
    Commit(nix_secrets_core::git::CommitOptions),
    DeleteProfile {
        name: String,
        revision: u64,
    },
}

enum Event {
    /// The worker's backend connection broke (`Some`) or works again.
    Connection(Option<String>),
    WorkerStopped,
    Progress(usize, usize, bool, bool),
    Phase(&'static str),
    ApprovalTerminated(String),
    Rows(Vec<Row>),
    Profiles(ProfileSnapshot),
    Approval(Box<ApprovalRequest>),
    Completion(Completion),
    Error(String),
    ApprovalLost(String),
}

/// Why an open deployment dialog closed when the backend connection broke.
pub const RECONNECTED_APPROVAL: &str = "The connection to the backend broke, so the open deployment request was discarded: nothing was deployed or saved from it, and its review must be read again. It opens again from its first step.";

struct WorkerCompletionGuard(Sender<Event>);
impl Drop for WorkerCompletionGuard {
    fn drop(&mut self) {
        let _ = self.0.send(Event::WorkerStopped);
    }
}

pub struct AsyncWriter {
    commands: Sender<Command>,
    events: Receiver<Event>,
    rows: Option<Vec<Row>>,
    profiles: Option<ProfileSnapshot>,
    approvals: Vec<ApprovalRequest>,
    completions: Vec<Completion>,
    busy: bool,
    pending: std::collections::VecDeque<Option<crate::model::Activity>>,
    drafts: std::collections::VecDeque<Option<(String, Zeroizing<Vec<u8>>)>>,
    activity: Option<crate::model::Activity>,
    /// Whether decryption goes through 1Password and may wait for approval.
    one_password: bool,
    /// Answers commit checks on their own connection, so they never wait
    /// behind the worker's queue.
    socket: Option<PathBuf>,
    /// Secret requests from the backend host; see `operator_channel`.
    channel: Option<Receiver<crate::operator_channel::ChannelEvent>>,
    decisions: Option<Sender<crate::operator_channel::OperatorInput>>,
    secret_prompts: Vec<crate::operator_channel::SecretPrompt>,
    /// Why the worker's or the operator channel's backend connection is
    /// down, while it is.
    worker_lost: Option<String>,
    channel_lost: Option<String>,
    /// The procedures listed while attaching again after a loss.
    attach_snapshot: Vec<String>,
    /// Shown while approved secret requests decrypt or sign, by request id.
    secret_activity: std::collections::BTreeMap<String, crate::model::Activity>,
    /// Procedure news from the operator channel, for the UI.
    procedure_events: Vec<ProcedureEvent>,
}

impl AsyncWriter {
    pub fn spawn(mut controller: Controller, socket: PathBuf) -> Self {
        let one_password = controller.uses_one_password();
        let check_socket = socket.clone();
        let (commands, incoming) = mpsc::channel();
        let (outgoing, events) = mpsc::channel();
        let progress = outgoing.clone();
        controller.set_progress(move |done, total, waiting| {
            let _ = progress.send(Event::Progress(done, total, waiting, false));
        });
        let phases = outgoing.clone();
        controller.set_phase(move |label| {
            let _ = phases.send(Event::Phase(label));
        });
        let (channel, decisions) = spawn_operator_channel(&controller, &socket, outgoing.clone());
        std::thread::spawn(move || {
            let _worker_completion = WorkerCompletionGuard(outgoing.clone());
            controller.set_reconnect(socket.clone());
            controller.start_background_refresh(socket);
            loop {
                match controller.reconnect_if_broken() {
                    Some(crate::controller::Reconnected::Again { lost_approval }) => {
                        if lost_approval.is_some()
                            && outgoing.send(Event::ApprovalLost(RECONNECTED_APPROVAL.into())).is_err()
                        {
                            return;
                        }
                        if outgoing.send(Event::Connection(None)).is_err() {
                            return;
                        }
                    }
                    Some(crate::controller::Reconnected::Failed(error)) => {
                        if outgoing.send(Event::Connection(Some(error))).is_err() {
                            return;
                        }
                    }
                    None => {}
                }
                if controller.disconnected() {
                    // Nothing reaches the backend until it is back.
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                match incoming.recv_timeout(Duration::from_millis(25)) {
                    Ok(command) => {
                        let approval_id = if matches!(
                            &command,
                            Command::Approval(_)
                                | Command::ApprovalWith(_, _)
                                | Command::HostMutations(_, _)
                        ) {
                            controller.active_approval_id()
                        } else {
                            None
                        };
                        let completion = match command {
                            Command::BulkGenerate { paths, kind } => {
                                execute_bulk(&mut controller, paths, kind, &outgoing)
                            }
                            other => execute(&mut controller, other),
                        };
                        if matches!(
                            &completion,
                            Completion::Deployed { .. }
                                | Completion::ApprovalDone(None)
                                | Completion::HostMutationsDeclined { .. }
                        ) {
                            if let Some(id) = approval_id {
                                let _ = outgoing.send(Event::ApprovalTerminated(id));
                            }
                        }
                        if outgoing.send(Event::Completion(completion)).is_err() {
                            return;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                match controller.refresh_rows() {
                    Ok(Some(rows)) => {
                        if outgoing.send(Event::Rows(rows)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if outgoing.send(Event::Error(error)).is_err() {
                            return;
                        }
                    }
                }
                match controller.refresh_profiles() {
                    Ok(Some(snapshot)) => {
                        if outgoing.send(Event::Profiles(snapshot)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if outgoing.send(Event::Error(error)).is_err() {
                            return;
                        }
                    }
                }
                match controller.poll_approval() {
                    Ok(Some(request)) => {
                        if outgoing.send(Event::Approval(Box::new(request))).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if outgoing.send(Event::ApprovalLost(error)).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        Self {
            commands,
            events,
            rows: None,
            profiles: None,
            approvals: vec![],
            completions: vec![],
            busy: false,
            pending: Default::default(),
            drafts: Default::default(),
            activity: None,
            one_password,
            socket: Some(check_socket),
            channel: Some(channel),
            decisions: Some(decisions),
            secret_prompts: vec![],
            secret_activity: Default::default(),
            procedure_events: vec![],
            worker_lost: None,
            channel_lost: None,
            attach_snapshot: vec![],
        }
    }

    fn pump(&mut self) {
        if let Some(channel) = &self.channel {
            use crate::operator_channel::ChannelEvent;
            while let Ok(event) = channel.try_recv() {
                match event {
                    ChannelEvent::Attached => {
                        let live = std::mem::take(&mut self.attach_snapshot);
                        if self.channel_lost.take().is_some() {
                            self.procedure_events.push(ProcedureEvent::Synced(live));
                            self.procedure_events.push(ProcedureEvent::Reconnected);
                        }
                    }
                    ChannelEvent::Prompt(prompt) => self.secret_prompts.push(prompt),
                    ChannelEvent::Withdrawn(id) => {
                        self.secret_prompts.retain(|prompt| prompt.id != id);
                        self.procedure_events.push(ProcedureEvent::Withdrawn(id));
                    }
                    ChannelEvent::Procedure(step) => {
                        if self.channel_lost.is_some() {
                            self.attach_snapshot.push(step.id.clone());
                        }
                        self.procedure_events.push(ProcedureEvent::Step(step))
                    }
                    ChannelEvent::ProcedureEnded(id) => {
                        self.procedure_events.push(ProcedureEvent::Ended(id))
                    }
                    ChannelEvent::Finished { id, requester, result } => {
                        self.secret_activity.remove(&id);
                        self.completions
                            .push(Completion::SecretRequestFinished { id, requester, result })
                    }
                    ChannelEvent::SignatureFinished { id, requester, result } => {
                        self.secret_activity.remove(&id);
                        self.completions.push(Completion::SshSignatureFinished { id, requester, result });
                    }
                    ChannelEvent::ArtifactSignatureFinished { id, requester, result } => {
                        self.secret_activity.remove(&id);
                        self.completions.push(Completion::ArtifactSignatureFinished { id, requester, result });
                    }
                    ChannelEvent::Lost(error) => {
                        // Requests on screen cannot be answered on the lost
                        // channel; the backend sends them again.
                        if self.channel_lost.is_none() {
                            self.procedure_events.push(ProcedureEvent::Disconnected);
                        }
                        self.secret_prompts.clear();
                        self.secret_activity.clear();
                        self.channel_lost = Some(error);
                    }
                }
            }
        }
        loop {
            let event = match self.events.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.worker_stopped();
                    break;
                }
            };
            match event {
                Event::WorkerStopped => self.worker_stopped(),
                Event::Connection(state) => self.worker_lost = state,
                Event::ApprovalTerminated(id) => {
                    self.completions.push(Completion::ApprovalTerminated(id))
                }
                Event::Phase(label) => {
                    if let Some(activity) = &mut self.activity {
                        activity.label = label.into();
                        activity.waits_for_one_password = false;
                    }
                }
                Event::Progress(done, total, waiting, secret) => {
                    let targets: Vec<&mut crate::model::Activity> = if secret {
                        self.secret_activity.values_mut().collect()
                    } else {
                        self.activity.iter_mut().collect()
                    };
                    for activity in targets {
                        activity.label = format!(
                            "Decrypting {done}/{total}. {}",
                            if waiting {
                                "Waiting for 1Password approval"
                            } else {
                                "Running decryption workers"
                            }
                        );
                        activity.waits_for_one_password = waiting;
                    }
                }
                Event::Rows(rows) => self.rows = Some(rows),
                Event::Profiles(snapshot) => self.profiles = Some(snapshot),
                Event::Approval(request) => self.approvals.push(*request),
                Event::Completion(mut result) => {
                    if !matches!(result, Completion::BulkProgress { .. }) {
                        self.pending.pop_front();
                        if let Some(Some((path, value))) = self.drafts.pop_front() {
                            if let Completion::Failed(message) = result {
                                result = Completion::SaveFailed {
                                    path,
                                    value,
                                    message,
                                };
                            }
                        }
                        self.busy = !self.pending.is_empty();
                        self.activity = self.pending.front().cloned().flatten();
                    }
                    self.completions.push(result);
                }
                Event::Error(error) => self.completions.push(Completion::Failed(error)),
                Event::ApprovalLost(error) => {
                    self.completions.push(Completion::ApprovalLost(error))
                }
            }
        }
    }

    fn worker_stopped(&mut self) {
        let had_drafts = self.drafts.iter().any(Option::is_some);
        for (path, value) in self.drafts.drain(..).flatten() {
            self.completions.push(Completion::SaveFailed {
                path,
                value,
                message: "backend worker stopped; this submitted value was retained for retry"
                    .into(),
            });
        }
        if self.busy && !had_drafts {
            self.completions
                .push(Completion::Failed("backend worker stopped".into()));
        }
        self.pending.clear();
        self.busy = false;
        self.activity = None;
    }

    fn queue(&mut self, command: Command) -> Result<(), String> {
        if self.busy {
            return Err("another operation is still running".into());
        }
        let activity = describe(&command, self.one_password);
        self.commands
            .send(command)
            .map_err(|_| "backend worker stopped".to_string())?;
        self.busy = true;
        self.pending.push_back(activity.clone());
        self.drafts.push_back(None);
        self.activity = activity;
        Ok(())
    }
}

mod execute;
use execute::execute;

mod bulk;
use bulk::execute_bulk;

impl SecretWriter for AsyncWriter {
    fn refresh_profiles(&mut self) -> Result<Option<ProfileSnapshot>, String> {
        self.pump();
        Ok(self.profiles.take())
    }
    fn save_profile(
        &mut self,
        name: String,
        profile: ViewProfile,
        revision: u64,
    ) -> Result<ProfileSnapshot, String> {
        self.queue(Command::SaveProfile {
            name,
            profile,
            revision,
        })?;
        Err(OPERATION_QUEUED.into())
    }
    fn delete_profile(&mut self, name: String, revision: u64) -> Result<ProfileSnapshot, String> {
        self.queue(Command::DeleteProfile { name, revision })?;
        Err(OPERATION_QUEUED.into())
    }
    fn commit_summary(&mut self) -> Result<nix_secrets_core::git::CommitSummary, String> {
        self.queue(Command::CommitSummary)?;
        Err(OPERATION_QUEUED.into())
    }
    fn commit(
        &mut self,
        options: nix_secrets_core::git::CommitOptions,
    ) -> Result<nix_secrets_core::git::CommitResult, String> {
        self.queue(Command::Commit(options))?;
        Err(OPERATION_QUEUED.into())
    }
    fn poll_completion(&mut self) -> Option<Completion> {
        self.pump();
        if self.completions.is_empty() {
            None
        } else {
            Some(self.completions.remove(0))
        }
    }

    fn refresh_rows(&mut self) -> Result<Option<Vec<Row>>, String> {
        self.pump();
        Ok(self.rows.take())
    }

    fn poll_approval(&mut self) -> Result<Option<ApprovalRequest>, String> {
        self.pump();
        if self.approvals.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.approvals.remove(0)))
        }
    }

    fn write(
        &mut self,
        path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        if value.len() > nix_secrets_crypto::MAX_SECRET_SIZE {
            return Err(("value exceeds the maximum secret size".into(), value));
        }
        if self.pending.len() >= 8 {
            return Err((
                "save queue is full; keep this value and retry after a save completes".into(),
                value,
            ));
        }
        let retained = value.clone();
        match self.commands.send(Command::Write {
            path: path.into(),
            value,
        }) {
            Ok(()) => {
                self.busy = true;
                let next = Some(activity(
                    format!("Encrypting and saving {path}"),
                    self.one_password,
                ));
                if self.pending.is_empty() {
                    self.activity = next.clone();
                }
                self.pending.push_back(next);
                self.drafts.push_back(Some((path.into(), retained)));
                Ok(Action::Queued)
            }
            Err(mpsc::SendError(Command::Write { value, .. })) => {
                Err(("backend worker stopped".into(), value))
            }
            Err(_) => unreachable!(),
        }
    }

    fn delete(&mut self, path: &str) -> Result<(), String> {
        self.queue(Command::Delete(path.into()))?;
        Err(OPERATION_QUEUED.into())
    }

    fn reveal(&mut self, path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        self.queue(Command::Reveal(path.into()))?;
        Err(OPERATION_QUEUED.into())
    }

    fn copy_public(&mut self, path: &str) -> Result<(), String> {
        self.queue(Command::CopyPublic(path.into()))?;
        Err(OPERATION_QUEUED.into())
    }

    fn generate(&mut self, path: &str, kind: GenerateKind) -> Result<Zeroizing<Vec<u8>>, String> {
        self.generate_for(path, kind, false)
    }

    fn generate_for(
        &mut self,
        path: &str,
        kind: GenerateKind,
        replacing: bool,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        self.queue(Command::Generate {
            path: path.into(),
            kind,
            replacing,
        })?;
        Err(OPERATION_QUEUED.into())
    }

    fn approval(&mut self, accepted: bool) -> Result<Option<ApprovalRequest>, String> {
        self.queue(Command::Approval(accepted))?;
        Err(OPERATION_QUEUED.into())
    }

    fn approval_with(
        &mut self,
        accepted: bool,
        unchecked: &std::collections::BTreeSet<String>,
    ) -> Result<Option<ApprovalRequest>, String> {
        self.queue(Command::ApprovalWith(accepted, unchecked.clone()))?;
        Err(OPERATION_QUEUED.into())
    }

    fn approve_host_mutations(
        &mut self,
        accepted: bool,
        token: &str,
    ) -> Result<Option<ApprovalRequest>, String> {
        self.queue(Command::HostMutations(accepted, token.to_owned()))?;
        Err(OPERATION_QUEUED.into())
    }

    fn request_deployment(&mut self, host: &str) -> Result<(), String> {
        self.queue(Command::RequestDeployment(host.to_owned()))
    }

    fn generate_keypair(&mut self, path: &str) -> Result<(), String> {
        self.queue(Command::GenerateKeypair(path.into()))?;
        Err(OPERATION_QUEUED.into())
    }

    fn generate_missing(&mut self, paths: Vec<String>, kind: GenerateKind) -> Result<(), String> {
        self.queue(Command::BulkGenerate { paths, kind })
    }

    fn copy(&mut self, value: &[u8]) -> Result<(), String> {
        self.queue(Command::CopyValue(Zeroizing::new(value.to_vec())))?;
        Err(OPERATION_QUEUED.into())
    }

    // The clipboard is local and quick to read, so this runs on the UI thread.
    fn paste(&mut self) -> Result<Zeroizing<Vec<u8>>, String> {
        crate::clipboard::paste()
    }

    fn commit_state(&mut self, path: &str) -> nix_secrets_core::CommitState {
        use nix_secrets_core::CommitState;
        let Some(socket) = &self.socket else {
            return CommitState::Unknown {
                reason: "no backend connection".into(),
            };
        };
        let result = (|| -> Result<CommitState, String> {
            let path =
                nix_secrets_core::SecretPath::parse(path).map_err(|error| error.to_string())?;
            let stream =
                crate::socket::connect_verified(socket).map_err(|error| error.to_string())?;
            crate::client::BackendClient::new(stream)
                .commit_state(&path)
                .map_err(|error| error.to_string())
        })();
        result.unwrap_or_else(|reason| CommitState::Unknown { reason })
    }

    fn connection_problem(&mut self) -> Option<String> {
        self.pump();
        self.worker_lost
            .clone()
            .or_else(|| self.channel_lost.clone())
    }

    fn poll_procedure_event(&mut self) -> Option<ProcedureEvent> {
        self.pump();
        (!self.procedure_events.is_empty()).then(|| self.procedure_events.remove(0))
    }

    fn cancel_countdown(&mut self, id: &str) -> Result<(), String> {
        self.decisions
            .as_ref()
            .ok_or("secret requests are unavailable")?
            .send(crate::operator_channel::OperatorInput::CancelCountdown(id.to_owned()))
            .map_err(|_| "the secret request channel stopped".to_string())
    }

    fn poll_secret_prompt(&mut self) -> Option<crate::operator_channel::SecretPrompt> {
        self.pump();
        (!self.secret_prompts.is_empty()).then(|| self.secret_prompts.remove(0))
    }

    fn answer_secret(&mut self, id: &str, approved: bool, count: usize) -> Result<(), String> {
        self.decisions
            .as_ref()
            .ok_or("secret requests are unavailable")?
            .send(
                crate::operator_channel::Decision {
                    id: id.to_owned(),
                    approved,
                }
                .into(),
            )
            .map_err(|_| "the secret request channel stopped".to_string())?;
        if approved {
            self.secret_activity.insert(id.to_owned(), activity(
                if count == 0 {
                    "Signing on this client; the private key stays here".into()
                } else {
                    format!(
                        "Decrypting {count} requested value{}",
                        if count == 1 { "" } else { "s" }
                    )
                },
                self.one_password,
            ));
        }
        Ok(())
    }

    fn activity(&mut self) -> Option<crate::model::Activity> {
        self.pump();
        let mut activity = self
            .activity
            .clone()
            .or_else(|| self.secret_activity.values().next().cloned())
            .or_else(|| self.pending.iter().find_map(Clone::clone));
        if let Some(value) = &mut activity {
            if self.pending.len() > 1 {
                value
                    .label
                    .push_str(&format!("; {} saves queued", self.pending.len() - 1));
            }
        }
        activity
    }
}

/// Starts the operator channel on its own connection and thread.
fn spawn_operator_channel(
    controller: &Controller,
    socket: &std::path::Path,
    progress: Sender<Event>,
) -> (
    Receiver<crate::operator_channel::ChannelEvent>,
    Sender<crate::operator_channel::OperatorInput>,
) {
    use crate::operator_channel::{run, ChannelEvent};
    let (schema, mut provider) = controller.schema_and_provider();
    provider.set_progress(move |done, total, waiting| {
        let _ = progress.send(Event::Progress(done, total, waiting, true));
    });
    let identity = provider.identity_description();
    let socket = socket.to_owned();
    let (events, channel) = mpsc::channel();
    let (decisions, incoming) = mpsc::channel();
    std::thread::spawn(move || {
        crate::operator_channel::run_reconnecting(
            &socket,
            &schema,
            &provider,
            &identity,
            &events,
            &incoming,
            Duration::from_secs(1),
        )
    });
    (channel, decisions)
}

fn activity(label: String, waits_for_one_password: bool) -> crate::model::Activity {
    crate::model::Activity {
        label,
        waits_for_one_password,
        started: std::time::Instant::now(),
    }
}

/// Names the slow commands; quick clipboard and profile edits show nothing.
fn describe(command: &Command, one_password: bool) -> Option<crate::model::Activity> {
    let (label, decrypts) = match command {
        Command::Reveal(path) => (format!("Decrypting {path}"), true),
        Command::Approval(true) | Command::ApprovalWith(true, _) => {
            ("Decrypting values for deployment".into(), true)
        }
        Command::HostMutations(accepted, _) => (
            if *accepted {
                "Saving approved host-provided changes"
            } else {
                "Rejecting host-provided changes"
            }
            .into(),
            false,
        ),
        Command::ApprovalWith(false, _) => ("Rejecting deployment request".into(), false),
        Command::Approval(false) => ("Rejecting deployment request".into(), false),
        Command::RequestDeployment(host) => (format!("Requesting a deployment of {host}"), false),
        // Saving verifies private keys and task values by decrypting them.
        Command::Write { path, .. } => (format!("Encrypting and saving {path}"), true),
        Command::Delete(path) => (format!("Deleting {path}"), false),
        Command::Generate { path, .. } => (format!("Generating {path}"), false),
        Command::GenerateKeypair(path) => (format!("Running the generator for {path}"), false),
        Command::BulkGenerate { paths, .. } => (
            format!("Generating {} missing passwords", paths.len()),
            false,
        ),
        Command::Commit(options) => (
            if options.amend {
                "Amending the last commit; sign it if your agent asks".into()
            } else {
                "Committing; sign it if your agent asks".into()
            },
            false,
        ),
        Command::CopyPublic(_)
        | Command::CopyValue(_)
        | Command::SaveProfile { .. }
        | Command::DeleteProfile { .. }
        | Command::CommitSummary => return None,
    };
    Some(activity(label, decrypts && one_password))
}

#[cfg(test)]
mod tests;
