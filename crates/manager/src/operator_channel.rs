//! The TUI end of secret requests: an operator connection to the backend
//! that receives requests from processes on the backend host, asks the
//! operator in a modal, decrypts after approval with one provider batch, and
//! returns the plaintexts on this authenticated connection.
//!
//! The channel runs on its own threads and its own connection, so a request
//! reaches the operator even while the worker runs a slow operation. Several
//! requests may wait at once, each on a thread of its own; the operator
//! answers them in any order. The backend also reports the procedures its
//! requesters run (see [`nix_secrets_core::procedure`]), so the TUI can
//! group their prompts.
use crate::client::BackendClient;
use crate::secret_values::{self, RequestedValue};
use crate::socket::connect_verified;
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::framing::{read_json, write_json, write_json_sensitive};
use nix_secrets_core::procedure::ProcedureStep;
use nix_secrets_core::secret_request::{ProcessInfo, SecretAnswer, SecretRequest, SecretValue};
use nix_secrets_core::{Request, Response, Schema};
use nix_secrets_crypto::CryptoProvider;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long the modal of a counting-down request waits before it denies on
/// its own. Only a request outside a procedure, or the first step of one,
/// counts down, and the operator can cancel it.
pub const DECISION_TIMEOUT: Duration = Duration::from_secs(120);

/// What the modal shows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretPrompt {
    pub id: String,
    pub values: Vec<RequestedValue>,
    /// Where the private key comes from, for example 1Password.
    pub identity: String,
    pub requester: ProcessInfo,
    pub parent: Option<ProcessInfo>,
    pub reason: Option<String>,
    pub ssh_signature: bool,
    pub artifact_signature: bool,
    pub closure_signature: bool,
    /// When the request denies itself; `None` when it waits for the
    /// operator: a later step of a procedure, or a cancelled countdown.
    pub deadline: Option<Instant>,
    /// The procedure step the backend verified, if the request has one.
    pub procedure: Option<ProcedureStep>,
}

impl SecretPrompt {
    /// Who asked, for notices: the parent's command, else the requester's.
    pub fn requester_label(&self) -> String {
        let process = self.parent.as_ref().unwrap_or(&self.requester);
        let command = process
            .argv
            .first()
            .map(|argument| {
                Path::new(argument)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| argument.clone())
            })
            .unwrap_or_else(|| "unknown program".into());
        format!("{command} (PID {})", process.pid)
    }
}

/// When a newly shown request denies itself, if it counts down.
pub(crate) fn deadline_for(request: &SecretRequest) -> Option<Instant> {
    request
        .countdown()
        .then(|| Instant::now() + DECISION_TIMEOUT)
}

/// Events from the channel to the UI.
pub enum ChannelEvent {
    /// The channel is attached; requests now reach this TUI.
    Attached,
    Prompt(SecretPrompt),
    /// The backend dropped this request: its requester left or the backend
    /// gave up. Its prompt closes; the request is denied.
    Withdrawn(String),
    /// A procedure started or reached a new step.
    Procedure(ProcedureStep),
    /// A procedure ended.
    ProcedureEnded(String),
    /// A request finished: `Ok` names the requester, `Err` explains.
    Finished {
        id: String,
        requester: String,
        result: Result<usize, String>,
    },
    SignatureFinished {
        id: String,
        requester: String,
        result: Result<(), String>,
    },
    ArtifactSignatureFinished {
        id: String,
        requester: String,
        result: Result<(), String>,
    },
    /// The channel stopped; requests can no longer reach this TUI.
    Lost(String),
}

/// Decisions from the UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    pub id: String,
    pub approved: bool,
}

/// What the UI sends the channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperatorInput {
    Decide(Decision),
    /// The operator stopped the automatic denial of this request; the
    /// backend and the requester are told.
    CancelCountdown(String),
}

impl From<Decision> for OperatorInput {
    fn from(decision: Decision) -> Self {
        Self::Decide(decision)
    }
}

/// What reaches the thread that handles one request.
enum HandlerInput {
    Decided(bool),
    CountdownCancelled,
    Withdrawn,
}

/// How waiting for the operator ended.
pub(crate) enum Waited {
    Approved,
    Denied,
    TimedOut,
    /// The backend withdrew the request.
    Withdrawn,
    /// The TUI or the channel closed.
    Closed,
}

/// The operator's decisions for one request.
pub(crate) struct Decisions {
    inputs: Receiver<HandlerInput>,
}

impl Decisions {
    /// Waits for the decision until `deadline`; a cancelled countdown waits
    /// without one from then on.
    pub(crate) fn wait(&self, mut deadline: Option<Instant>) -> Waited {
        loop {
            let timeout = deadline.map_or(Duration::from_secs(3600), |deadline| {
                deadline.saturating_duration_since(Instant::now())
            });
            match self.inputs.recv_timeout(timeout) {
                Ok(HandlerInput::Decided(true)) => return Waited::Approved,
                Ok(HandlerInput::Decided(false)) => return Waited::Denied,
                Ok(HandlerInput::CountdownCancelled) => deadline = None,
                Ok(HandlerInput::Withdrawn) => return Waited::Withdrawn,
                Err(RecvTimeoutError::Timeout) if deadline.is_some() => return Waited::TimedOut,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Waited::Closed,
            }
        }
    }
}

/// What the dispatcher learns from the backend reader and the handlers.
enum Internal {
    Frame(Response),
    Closed(io::Result<()>),
    Done(String),
}

/// Attaches as the operator and serves requests until the backend or UI
/// goes away.
pub fn run(
    socket: &Path,
    schema: &Schema,
    provider: &(impl CryptoProvider + Sync),
    identity: &str,
    events: &Sender<ChannelEvent>,
    decisions: &Receiver<OperatorInput>,
) -> io::Result<()> {
    run_with_agent(socket, schema, provider, identity, events, decisions, None)
}

/// An embedding client may select its own local agent explicitly.
pub fn run_with_agent(
    socket: &Path,
    schema: &Schema,
    provider: &(impl CryptoProvider + Sync),
    identity: &str,
    events: &Sender<ChannelEvent>,
    decisions: &Receiver<OperatorInput>,
    agent: Option<&Path>,
) -> io::Result<()> {
    let mut stream = connect_verified(socket)?;
    write_json(&mut stream, &Request::AttachOperator)?;
    match read_json::<Response>(&mut stream)? {
        Some(Response::OperatorAttached) => {
            if events.send(ChannelEvent::Attached).is_err() {
                return Ok(());
            }
        }
        other => {
            return Err(io::Error::other(format!(
                "the backend refused the operator channel: {other:?}"
            )))
        }
    }
    // Answers from several handlers and cancellations share the connection;
    // each frame is written whole under this lock.
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let (internal, inbox) = mpsc::channel::<Internal>();
    let mut handlers: BTreeMap<String, Sender<HandlerInput>> = BTreeMap::new();
    std::thread::scope(|scope| {
        let reader_internal = internal.clone();
        let mut reader = stream.try_clone()?;
        scope.spawn(move || loop {
            match read_json::<Response>(&mut reader) {
                Ok(Some(Response::Heartbeat)) => {}
                Ok(Some(frame)) => {
                    if reader_internal.send(Internal::Frame(frame)).is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = reader_internal.send(Internal::Closed(Ok(())));
                    return;
                }
                Err(error) => {
                    let _ = reader_internal.send(Internal::Closed(Err(error)));
                    return;
                }
            }
        });
        let result = loop {
            // Backend frames and finished handlers first, then the UI.
            let mut finished = None;
            while let Ok(message) = inbox.try_recv() {
                match message {
                    Internal::Frame(Response::SecretRequested { request }) => {
                        let (sender, inputs) = mpsc::channel();
                        handlers.insert(request.id.clone(), sender);
                        let (events, writer, internal) =
                            (events.clone(), Arc::clone(&writer), internal.clone());
                        scope.spawn(move || {
                            let decisions = Decisions { inputs };
                            let (answer, done) = match connect_verified(socket) {
                                Ok(stream) => handle(
                                    &request,
                                    &mut BackendClient::new(stream),
                                    schema,
                                    provider,
                                    identity,
                                    &events,
                                    &decisions,
                                    agent,
                                ),
                                Err(error) => refuse(
                                    &request,
                                    format!("cannot reach the backend: {error}"),
                                ),
                            };
                            let written = writer.lock().map_err(|_| ()).and_then(|mut stream| {
                                write_json_sensitive(
                                    &mut *stream,
                                    &Request::AnswerSecretRequest {
                                        request_id: request.id.clone(),
                                        answer,
                                    },
                                )
                                .map_err(|_| ())
                            });
                            if written.is_ok() {
                                let _ = events.send(done);
                            }
                            let _ = internal.send(Internal::Done(request.id.clone()));
                        });
                    }
                    Internal::Frame(Response::SecretRequestWithdrawn { request_id }) => {
                        if let Some(handler) = handlers.get(&request_id) {
                            let _ = handler.send(HandlerInput::Withdrawn);
                        }
                        if events.send(ChannelEvent::Withdrawn(request_id)).is_err() {
                            finished = Some(Ok(()));
                        }
                    }
                    Internal::Frame(Response::ProcedureUpdate { procedure }) => {
                        if events.send(ChannelEvent::Procedure(procedure)).is_err() {
                            finished = Some(Ok(()));
                        }
                    }
                    Internal::Frame(Response::ProcedureEnded { id }) => {
                        if events.send(ChannelEvent::ProcedureEnded(id)).is_err() {
                            finished = Some(Ok(()));
                        }
                    }
                    Internal::Frame(other) => {
                        finished = Some(Err(io::Error::other(format!(
                            "unexpected backend message: {other:?}"
                        ))))
                    }
                    Internal::Closed(result) => finished = Some(result),
                    Internal::Done(id) => {
                        handlers.remove(&id);
                    }
                }
            }
            if let Some(result) = finished {
                break result;
            }
            match decisions.recv_timeout(Duration::from_millis(20)) {
                Ok(OperatorInput::Decide(decision)) => {
                    if let Some(handler) = handlers.get(&decision.id) {
                        let _ = handler.send(HandlerInput::Decided(decision.approved));
                    }
                }
                Ok(OperatorInput::CancelCountdown(id)) => {
                    if let Some(handler) = handlers.get(&id) {
                        let _ = handler.send(HandlerInput::CountdownCancelled);
                        let written = writer
                            .lock()
                            .map_err(|_| io::Error::other("operator connection lock poisoned"))
                            .and_then(|mut stream| {
                                write_json(&mut *stream, &Request::CancelCountdown { request_id: id })
                            });
                        if let Err(error) = written {
                            break Err(error);
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break Ok(()),
            }
        };
        // Waiting handlers deny once their decisions channel closes. Their
        // answers reach the backend before the connection closes, so each
        // requester learns why; a handler busy decrypting gets a moment.
        let outstanding = handlers.len();
        handlers.clear();
        let until = Instant::now() + Duration::from_secs(5);
        let mut done = 0;
        while done < outstanding {
            match inbox.recv_timeout(until.saturating_duration_since(Instant::now())) {
                Ok(Internal::Done(_)) => done += 1,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        // The reader stops with the connection.
        let _ = stream.shutdown(std::net::Shutdown::Both);
        result
    })
}

/// Denies a request before anyone was asked.
fn refuse(request: &SecretRequest, reason: String) -> (SecretAnswer, ChannelEvent) {
    (
        SecretAnswer::Denied {
            reason: reason.clone(),
        },
        ChannelEvent::Finished {
            id: request.id.clone(),
            requester: format!("PID {}", request.requester.pid),
            result: Err(reason),
        },
    )
}

/// Why waiting ended without an approval, for the requester.
pub(crate) fn not_approved(waited: Waited, what: &str) -> String {
    match waited {
        Waited::Approved => unreachable!("approval is not a refusal"),
        Waited::Denied => format!("the operator denied {what}"),
        Waited::TimedOut => format!(
            "the operator did not answer {what} within {} seconds",
            DECISION_TIMEOUT.as_secs()
        ),
        Waited::Withdrawn => format!("{what} was withdrawn by the backend"),
        Waited::Closed => "the nix-secrets TUI closed".into(),
    }
}

fn handle(
    request: &SecretRequest,
    client: &mut BackendClient,
    schema: &Schema,
    provider: &impl CryptoProvider,
    identity: &str,
    events: &Sender<ChannelEvent>,
    decisions: &Decisions,
    agent: Option<&Path>,
) -> (SecretAnswer, ChannelEvent) {
    if let Some(signature) = &request.closure_signature {
        return crate::closure_signing::handle(
            request, signature, client, schema, provider, identity, events, decisions,
        );
    }
    if let Some(signature) = &request.artifact_signature {
        return crate::artifact_signing::handle(
            request, signature, client, schema, provider, identity, events, decisions,
        );
    }
    if let Some(signature) = &request.ssh_signature {
        return handle_signature(request, signature, schema, events, decisions, agent);
    }
    let prompt_for = |values| SecretPrompt {
        id: request.id.clone(),
        values,
        identity: identity.to_owned(),
        requester: request.requester.clone(),
        parent: request.parent.clone(),
        reason: request.reason.clone(),
        ssh_signature: false,
        artifact_signature: false,
        closure_signature: false,
        deadline: deadline_for(request),
        procedure: request.procedure.clone(),
    };
    let label = prompt_for(Vec::new()).requester_label();
    let deny = |reason: String| {
        (
            SecretAnswer::Denied {
                reason: reason.clone(),
            },
            ChannelEvent::Finished {
                id: request.id.clone(),
                requester: label.clone(),
                result: Err(reason),
            },
        )
    };
    // Invalid or unset values are refused before anyone is asked.
    let batch = match secret_values::load(client, schema, &request.identifiers) {
        Ok(batch) => batch,
        Err(error) => return deny(format!("secret request refused: {error}")),
    };
    let prompt = prompt_for(batch.values.clone());
    let deadline = prompt.deadline;
    if events.send(ChannelEvent::Prompt(prompt)).is_err() {
        return deny("the nix-secrets TUI closed".into());
    }
    match decisions.wait(deadline) {
        Waited::Approved => {}
        Waited::TimedOut => {
            return deny(format!(
                "the operator did not answer within {} seconds",
                DECISION_TIMEOUT.as_secs()
            ))
        }
        Waited::Denied => return deny("the operator denied the secret request".into()),
        other => return deny(not_approved(other, "the secret request")),
    }
    match batch.decrypt(provider) {
        Ok(values) => {
            let count = values.len();
            let values = values
                .into_iter()
                .map(|(identifier, value)| SecretValue {
                    identifier,
                    value_base64: STANDARD.encode(value.as_slice()),
                })
                .collect();
            (
                SecretAnswer::Approved { values },
                ChannelEvent::Finished {
                    id: request.id.clone(),
                    requester: label,
                    result: Ok(count),
                },
            )
        }
        Err(error) => deny(format!("decryption failed: {error}")),
    }
}

fn handle_signature(
    request: &SecretRequest,
    signature: &nix_secrets_core::ssh_auth::SignatureRequest,
    schema: &Schema,
    events: &Sender<ChannelEvent>,
    decisions: &Decisions,
    agent: Option<&Path>,
) -> (SecretAnswer, ChannelEvent) {
    let agent_names = crate::key_names::AgentKeys::from_agent(agent.and_then(|path| path.to_str()));
    let key_name = crate::key_names::describe(schema, &agent_names, &signature.public_key);
    let mut prompt = SecretPrompt {
        id: request.id.clone(),
        values: vec![RequestedValue {
            identifier: signature.destination.clone(), kind: "SSH authentication".into(),
            description: Some(format!("Signing key: {key_name}. The destination is declared by the requester and cannot be verified from an agent challenge.")),
            recipients: vec![],
        }],
        identity: "client SSH agent".into(), requester: request.requester.clone(),
        parent: request.parent.clone(), reason: request.reason.clone(), ssh_signature: true,
        artifact_signature: false,
        closure_signature: false,
        deadline: deadline_for(request),
        procedure: request.procedure.clone(),
    };
    let label = prompt.requester_label();
    let deny = |reason: String| {
        (
            SecretAnswer::Denied {
                reason: reason.clone(),
            },
            ChannelEvent::SignatureFinished {
                id: request.id.clone(),
                requester: label.clone(),
                result: Err(reason),
            },
        )
    };
    if !request.identifiers.is_empty() {
        return deny("SSH signatures cannot request secret values".into());
    }
    if let Err(error) = signature.validate() {
        return deny(error);
    }
    let socket = match signature_agent(&signature.public_key, agent) {
        Ok(socket) => socket,
        Err(error) => return deny(error),
    };
    prompt.identity = if socket.ends_with(".1password/agent.sock") {
        "1Password SSH agent on this client".into()
    } else {
        "SSH agent on this client".into()
    };
    let deadline = prompt.deadline;
    if events.send(ChannelEvent::Prompt(prompt)).is_err() {
        return deny("the TUI closed".into());
    }
    match decisions.wait(deadline) {
        Waited::Approved => {}
        Waited::Denied => return deny("the operator denied SSH authentication".into()),
        Waited::TimedOut => {
            return deny("the operator did not approve SSH authentication in time".into())
        }
        other => return deny(not_approved(other, "SSH authentication")),
    }
    match nix_secrets_core::ssh_auth::sign(&socket, signature) {
        Ok(reply) => (
            SecretAnswer::Signed { reply },
            ChannelEvent::SignatureFinished {
                id: request.id.clone(),
                requester: label,
                result: Ok(()),
            },
        ),
        Err(error) => deny(error),
    }
}

fn signature_agent(
    public_key: &str,
    selected: Option<&Path>,
) -> Result<std::path::PathBuf, String> {
    let mut sockets = Vec::new();
    if let Some(selected) = selected {
        sockets.push(selected.to_owned());
    } else {
        if let Some(home) = std::env::var_os("HOME") {
            sockets.push(std::path::PathBuf::from(home).join(".1password/agent.sock"));
        }
        if let Some(socket) = std::env::var_os("SSH_AUTH_SOCK") {
            sockets.push(socket.into());
        }
    }
    let key = nix_secrets_core::ssh_auth::key_blob(public_key)?;
    for socket in sockets {
        if let Ok(keys) = nix_secrets_transport::agent_keys(Some(&socket.to_string_lossy())) {
            if keys.iter().any(|line| {
                nix_secrets_core::ssh_auth::key_blob(line).is_ok_and(|blob| blob == key)
            }) {
                return Ok(socket);
            }
        }
    }
    Err(format!(
        "the SSH key {} is absent from this client's agents",
        crate::key_names::short_fingerprint(public_key)
    ))
}
