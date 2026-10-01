//! The TUI end of secret requests: an operator connection to the backend
//! that receives requests from processes on the backend host, asks the
//! operator in a modal, decrypts after approval with one provider batch, and
//! returns the plaintexts on this authenticated connection.
//!
//! The channel runs on its own thread and its own connection, so a request
//! reaches the operator even while the worker runs a slow operation.
use crate::client::BackendClient;
use crate::secret_values::{self, RequestedValue};
use crate::socket::connect_verified;
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::framing::{read_json, write_json, write_json_sensitive};
use nix_secrets_core::secret_request::{ProcessInfo, SecretAnswer, SecretRequest, SecretValue};
use nix_secrets_core::{Request, Response, Schema};
use nix_secrets_crypto::CryptoProvider;
use std::io;
use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

/// How long the modal waits before it denies on its own.
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
    /// When the request denies itself.
    pub deadline: Instant,
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

/// Events from the channel to the UI.
pub enum ChannelEvent {
    /// The channel is attached; requests now reach this TUI.
    Attached,
    Prompt(SecretPrompt),
    /// A request finished: `Ok` names the requester, `Err` explains.
    Finished {
        requester: String,
        result: Result<usize, String>,
    },
    SignatureFinished {
        requester: String,
        result: Result<(), String>,
    },
    ArtifactSignatureFinished { requester: String, result: Result<(), String> },
    /// The channel stopped; requests can no longer reach this TUI.
    Lost(String),
}

/// Decisions from the UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    pub id: String,
    pub approved: bool,
}

/// Attaches as the operator and serves requests until the backend or UI
/// goes away.
pub fn run(
    socket: &Path,
    schema: &Schema,
    provider: &impl CryptoProvider,
    identity: &str,
    events: &Sender<ChannelEvent>,
    decisions: &Receiver<Decision>,
) -> io::Result<()> {
    run_with_agent(socket, schema, provider, identity, events, decisions, None)
}

/// An embedding client may select its own local agent explicitly.
pub fn run_with_agent(
    socket: &Path,
    schema: &Schema,
    provider: &impl CryptoProvider,
    identity: &str,
    events: &Sender<ChannelEvent>,
    decisions: &Receiver<Decision>,
    agent: Option<&Path>,
) -> io::Result<()> {
    let mut stream = connect_verified(socket)?;
    let mut client = BackendClient::new(connect_verified(socket)?);
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
    loop {
        let request = match read_json::<Response>(&mut stream)? {
            Some(Response::Heartbeat) => continue,
            Some(Response::SecretRequested { request }) => request,
            Some(other) => {
                return Err(io::Error::other(format!(
                    "unexpected backend message: {other:?}"
                )))
            }
            None => return Ok(()),
        };
        let (answer, finished) = handle(
            &request,
            &mut client,
            schema,
            provider,
            identity,
            events,
            decisions,
            agent,
        );
        write_json_sensitive(
            &mut stream,
            &Request::AnswerSecretRequest {
                request_id: request.id.clone(),
                answer,
            },
        )?;
        if events.send(finished).is_err() {
            return Ok(());
        }
    }
}

fn handle(
    request: &SecretRequest,
    client: &mut BackendClient,
    schema: &Schema,
    provider: &impl CryptoProvider,
    identity: &str,
    events: &Sender<ChannelEvent>,
    decisions: &Receiver<Decision>,
    agent: Option<&Path>,
) -> (SecretAnswer, ChannelEvent) {
    if let Some(signature) = &request.artifact_signature {
        return crate::artifact_signing::handle(request, signature, client, schema, provider, identity, events, decisions);
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
        deadline: Instant::now() + DECISION_TIMEOUT,
    };
    let label = prompt_for(Vec::new()).requester_label();
    let deny = |reason: String| {
        (
            SecretAnswer::Denied {
                reason: reason.clone(),
            },
            ChannelEvent::Finished {
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
    // Drop decisions left over from an earlier request.
    while decisions.try_recv().is_ok() {}
    if events.send(ChannelEvent::Prompt(prompt)).is_err() {
        return deny("the nix-secrets TUI closed".into());
    }
    let approved = loop {
        match decisions.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(decision) if decision.id == request.id => break decision.approved,
            Ok(_) => continue,
            Err(RecvTimeoutError::Timeout) => {
                return deny(format!(
                    "the operator did not answer within {} seconds",
                    DECISION_TIMEOUT.as_secs()
                ))
            }
            Err(RecvTimeoutError::Disconnected) => {
                return deny("the nix-secrets TUI closed".into())
            }
        }
    };
    if !approved {
        return deny("the operator denied the secret request".into());
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
    decisions: &Receiver<Decision>,
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
        deadline: Instant::now() + DECISION_TIMEOUT,
    };
    let label = prompt.requester_label();
    let deny = |reason: String| {
        (
            SecretAnswer::Denied {
                reason: reason.clone(),
            },
            ChannelEvent::SignatureFinished {
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
    while decisions.try_recv().is_ok() {}
    if events.send(ChannelEvent::Prompt(prompt)).is_err() {
        return deny("the TUI closed".into());
    }
    loop {
        match decisions.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(decision) if decision.id == request.id => {
                if !decision.approved {
                    return deny("the operator denied SSH authentication".into());
                }
                break;
            }
            Ok(_) => {}
            Err(_) => {
                return deny("the operator did not approve SSH authentication in time".into())
            }
        }
    }
    match nix_secrets_core::ssh_auth::sign(&socket, signature) {
        Ok(reply) => (
            SecretAnswer::Signed { reply },
            ChannelEvent::SignatureFinished {
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
