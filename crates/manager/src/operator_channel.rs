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
) -> (SecretAnswer, ChannelEvent) {
    let prompt_for = |values| SecretPrompt {
        id: request.id.clone(),
        values,
        identity: identity.to_owned(),
        requester: request.requester.clone(),
        parent: request.parent.clone(),
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
