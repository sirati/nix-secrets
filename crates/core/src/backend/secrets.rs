//! Secret requests from processes on the backend host.
//!
//! A TUI attaches as the operator on a dedicated connection
//! ([`Request::AttachOperator`]). A local process asks for a batch of values
//! with [`Request::RequestSecrets`]; the backend fills in who asked from
//! `/proc` of the connection's peer, forwards the request to the most
//! recently attached TUI and waits for its answer. The TUI decrypts after the
//! operator confirms and returns the plaintexts on its authenticated
//! connection. The backend then keeps them only in memory, in a
//! [`SecretSession`] served on a private socket, until the requester ends
//! the session or disconnects. Without an attached TUI the request fails; it
//! is never decrypted anywhere else.
use super::{Request, Response};
use crate::framing::{read_json, read_json_sensitive, write_json};
use crate::private_socket::runtime_directory;
use crate::secret_request::{
    parent_pid, ProcessInfo, SecretAnswer, SecretRequest, MAX_REQUEST_IDENTIFIERS,
};
use crate::secret_session::SecretSession;
use crate::SecretPath;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rustix::net::RecvFlags;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How long the backend waits for the operator. The TUI denies on its own
/// after 120 seconds without a decision; this bounds a TUI that stopped
/// answering, including the time a 1Password prompt may take after approval.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(600);
const HEARTBEAT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_secs(1);

pub const NO_OPERATOR: &str =
    "no nix-secrets TUI is attached to this backend; open the nix-secrets TUI and retry";

struct Job {
    request: SecretRequest,
    reply: Sender<Result<SecretAnswer, String>>,
}

#[derive(Default)]
pub(super) struct Operators {
    /// Attached TUIs in attach order; the last one receives requests.
    attached: Mutex<Vec<(u64, Sender<Job>)>>,
    /// Whether a request is waiting for the operator.
    pending: AtomicBool,
    next_request: AtomicU64,
}

/// Releases the single pending-request slot.
struct Pending<'a>(&'a AtomicBool);

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Operators {
    fn claim(&self) -> Result<Pending<'_>, String> {
        self.pending
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| Pending(&self.pending))
            .map_err(|_| {
                "another secret request is waiting for the operator; retry when it is answered"
                    .to_owned()
            })
    }

    fn latest(&self) -> Option<Sender<Job>> {
        self.attached
            .lock()
            .ok()?
            .last()
            .map(|(_, sender)| sender.clone())
    }
}

/// Serves an attached TUI until it disconnects.
pub(super) fn attach(
    stream: &mut UnixStream,
    operators: &Operators,
    session: u64,
) -> io::Result<()> {
    let (sender, jobs) = mpsc::channel::<Job>();
    operators
        .attached
        .lock()
        .map_err(|_| io::Error::other("operator registry lock is poisoned"))?
        .push((session, sender));
    let result = write_json(stream, &Response::OperatorAttached).and_then(|()| {
        let mut last_heartbeat = Instant::now();
        loop {
            match jobs.recv_timeout(POLL) {
                Err(RecvTimeoutError::Disconnected) => break Ok(()),
                Err(RecvTimeoutError::Timeout) => {
                    // The TUI sends nothing unasked: readable means it hung
                    // up or broke the protocol. Either way it is detached
                    // before the next request can be routed to it.
                    if peer_done(stream) {
                        break Ok(());
                    }
                    if last_heartbeat.elapsed() >= HEARTBEAT {
                        write_json(stream, &Response::Heartbeat)?;
                        last_heartbeat = Instant::now();
                    }
                }
                Ok(job) => {
                    let answer = ask(stream, &job.request);
                    let broken = answer.is_err();
                    let _ = job.reply.send(answer.map_err(|error| {
                        format!("the nix-secrets TUI did not answer the request: {error}")
                    }));
                    if broken {
                        break Ok(());
                    }
                }
            }
        }
    });
    if let Ok(mut attached) = operators.attached.lock() {
        attached.retain(|(id, _)| *id != session);
    }
    result
}

fn ask(stream: &mut UnixStream, request: &SecretRequest) -> io::Result<SecretAnswer> {
    write_json(
        stream,
        &Response::SecretRequested {
            request: request.clone(),
        },
    )?;
    stream.set_read_timeout(Some(ANSWER_TIMEOUT))?;
    let answer = read_json_sensitive::<Request>(stream);
    stream.set_read_timeout(None)?;
    match answer? {
        Some(Request::AnswerSecretRequest { request_id, answer }) if request_id == request.id => {
            Ok(answer)
        }
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the TUI sent something other than the answer",
        )),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the TUI disconnected",
        )),
    }
}

/// Handles [`Request::RequestSecrets`] from the process `peer`: asks the
/// operator and, if approved, serves the session until the requester ends it
/// or disconnects. Refusals are answered with [`Response::Error`].
pub(super) fn request(
    stream: &mut UnixStream,
    operators: &Operators,
    peer: u32,
    identifiers: Vec<String>,
    reason: Option<String>,
) -> io::Result<()> {
    let values = match approved_values(operators, peer, identifiers, reason) {
        Ok(values) => values,
        Err(message) => return write_json(stream, &Response::Error { message }),
    };
    let session = match SecretSession::bind(&runtime_directory(), values, peer) {
        Ok(session) => session,
        Err(error) => {
            return write_json(
                stream,
                &Response::Error {
                    message: format!("cannot create the secret session socket: {error}"),
                },
            );
        }
    };
    write_json(
        stream,
        &Response::SecretSession {
            socket: session.path().to_owned(),
        },
    )?;
    session.serve_until(|| peer_done(stream))?;
    // Removes the socket and erases every value before the acknowledgement.
    drop(session);
    if let Ok(Some(Request::EndSecretSession)) = read_json::<Request>(stream) {
        write_json(stream, &Response::SecretSessionEnded)?;
    }
    Ok(())
}

/// Whether the peer sent something or hung up.
fn peer_done(stream: &UnixStream) -> bool {
    let mut byte = [0_u8; 1];
    match rustix::net::recv(stream, &mut byte[..], RecvFlags::PEEK | RecvFlags::DONTWAIT) {
        Ok((_, 0)) => true,
        Ok(_) => true,
        Err(error) => error != rustix::io::Errno::AGAIN,
    }
}

fn approved_values(
    operators: &Operators,
    peer: u32,
    identifiers: Vec<String>,
    reason: Option<String>,
) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>, String> {
    if reason
        .as_ref()
        .is_some_and(|reason| reason.len() > crate::secret_request::MAX_REQUEST_REASON_BYTES)
    {
        return Err("secret request reason exceeds 4096 bytes".into());
    }
    if identifiers.is_empty() || identifiers.len() > MAX_REQUEST_IDENTIFIERS {
        return Err(format!(
            "a secret request names between 1 and {MAX_REQUEST_IDENTIFIERS} identifiers"
        ));
    }
    let mut seen = BTreeSet::new();
    for identifier in &identifiers {
        SecretPath::parse(identifier).map_err(|error| format!("{identifier}: {error}"))?;
        if !seen.insert(identifier.clone()) {
            return Err(format!("{identifier} is requested twice"));
        }
    }
    // At most one request waits for the operator at a time.
    let _pending = operators.claim()?;
    let operator = operators.latest().ok_or(NO_OPERATOR)?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    let request = SecretRequest {
        id: format!(
            "secret-{}-{}",
            operators.next_request.fetch_add(1, Ordering::Relaxed),
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
        identifiers,
        reason,
        requester: ProcessInfo::read(peer),
        parent: parent_pid(peer).map(ProcessInfo::read),
    };
    let (reply, answer) = mpsc::channel();
    operator
        .send(Job {
            request: request.clone(),
            reply,
        })
        .map_err(|_| NO_OPERATOR.to_owned())?;
    let answer = answer
        .recv_timeout(ANSWER_TIMEOUT + Duration::from_secs(10))
        .map_err(|_| "the nix-secrets TUI did not answer in time".to_owned())??;
    let values = match &answer {
        SecretAnswer::Denied { reason } => return Err(reason.clone()),
        SecretAnswer::Approved { values } => values,
    };
    let mut decoded = BTreeMap::new();
    for value in values {
        if !seen.contains(&value.identifier) {
            return Err(format!("the TUI returned {} unasked", value.identifier));
        }
        let bytes = STANDARD
            .decode(value.value_base64.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| {
                format!(
                    "the TUI returned a malformed value for {}",
                    value.identifier
                )
            })?;
        if decoded.insert(value.identifier.clone(), bytes).is_some() {
            return Err(format!("the TUI returned {} twice", value.identifier));
        }
    }
    if decoded.len() != seen.len() {
        return Err("the TUI did not return every requested value".into());
    }
    Ok(decoded)
}
