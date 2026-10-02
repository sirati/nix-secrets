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
use crate::SecretPath;
use crate::framing::{read_json, read_json_sensitive, write_json};
use crate::private_socket::runtime_directory;
use crate::secret_request::{
    MAX_REQUEST_IDENTIFIERS, ProcessInfo, SecretAnswer, SecretRequest, parent_pid,
};
use crate::secret_session::SecretSession;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustix::net::RecvFlags;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
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
    closure_requests: Mutex<BTreeMap<String, (UnixStream, u32)>>,
    operator_peers: Mutex<BTreeMap<u64, u32>>,
    artifacts: Mutex<BTreeMap<String, BTreeMap<String, std::fs::File>>>,
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

    fn latest(&self) -> Option<(u64, Sender<Job>)> {
        self.attached
            .lock()
            .ok()?
            .last()
            .map(|(id, sender)| (*id, sender.clone()))
    }
}

/// Serves an attached TUI until it disconnects.
pub(super) fn attach(
    stream: &mut UnixStream,
    operators: &Operators,
    session: u64,
    peer: u32,
) -> io::Result<()> {
    operators
        .operator_peers
        .lock()
        .map_err(|_| io::Error::other("operator peer registry poisoned"))?
        .insert(session, peer);
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
                    if let Ok(mut requests) = operators.closure_requests.lock() {
                        requests.remove(&job.request.id);
                    }
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
    if let Ok(mut peers) = operators.operator_peers.lock() {
        peers.remove(&session);
    }
    result
}

fn ask(stream: &mut UnixStream, request: &SecretRequest) -> io::Result<SecretAnswer> {
    ask_with_timeout(stream, request, ANSWER_TIMEOUT)
}

fn ask_with_timeout(
    stream: &mut UnixStream,
    request: &SecretRequest,
    timeout: Duration,
) -> io::Result<SecretAnswer> {
    write_json(
        stream,
        &Response::SecretRequested {
            request: request.clone(),
        },
    )?;
    stream.set_read_timeout(Some(timeout))?;
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
    schema: &crate::Schema,
) -> io::Result<()> {
    for identifier in &identifiers {
        let result = SecretPath::parse(identifier)
            .map_err(|e| e.to_string())
            .and_then(|path| schema.leaf(&path).map_err(|e| e.to_string()));
        match result {
            Ok(crate::LeafSpec::Operator(spec)) if spec.signing_only => {
                return write_json(
                    stream,
                    &Response::Error {
                        message: format!(
                            "{identifier} is signing-only; plaintext export is forbidden"
                        ),
                    },
                );
            }
            // Other value validation belongs to the operator channel, which
            // reports a refusal notice even when no approval is needed.
            _ => {}
        }
    }
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
    let answer = request_operator(operators, peer, identifiers, reason, None, None, None, None)?;
    let values = match &answer {
        SecretAnswer::Denied { reason } => return Err(reason.clone()),
        SecretAnswer::Approved { values } => values,
        SecretAnswer::Signed { .. }
        | SecretAnswer::ArtifactsSigned { .. }
        | SecretAnswer::ClosureSigned { .. } => {
            return Err("the TUI returned an unasked signature".into());
        }
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

fn request_operator(
    operators: &Operators,
    peer: u32,
    identifiers: Vec<String>,
    reason: Option<String>,
    ssh_signature: Option<crate::ssh_auth::SignatureRequest>,
    artifact_signature: Option<crate::artifact_signing::SigningRequest>,
    closure_signature: Option<crate::closure_signing::SigningRequest>,
    requester: Option<&UnixStream>,
) -> Result<SecretAnswer, String> {
    if reason
        .as_ref()
        .is_some_and(|r| r.len() > crate::secret_request::MAX_REQUEST_REASON_BYTES)
    {
        return Err("request reason exceeds 4096 bytes".into());
    }
    // At most one request waits for the operator at a time.
    let _pending = operators.claim()?;
    let (operator_session, operator) = operators.latest().ok_or(NO_OPERATOR)?;
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
        ssh_signature,
        artifact_signature,
        closure_signature,
        requester: ProcessInfo::read(peer),
        parent: parent_pid(peer).map(ProcessInfo::read),
    };
    // Pin immutable files before the request becomes visible. The frontend
    // can read only these files, by role and opaque request ID, while pending.
    let files = request
        .artifact_signature
        .as_ref()
        .map(open_artifacts)
        .transpose()?;
    if let Some(files) = files {
        operators
            .artifacts
            .lock()
            .map_err(|_| "artifact registry poisoned")?
            .insert(request.id.clone(), files);
    }
    struct Registered<'a>(&'a Operators, String);
    impl Drop for Registered<'_> {
        fn drop(&mut self) {
            if let Ok(mut requests) = self.0.closure_requests.lock() {
                requests.remove(&self.1);
            }
            if let Ok(mut files) = self.0.artifacts.lock() {
                files.remove(&self.1);
            }
        }
    }
    let _registered = Registered(operators, request.id.clone());
    if request.closure_signature.is_some() {
        let owner = *operators
            .operator_peers
            .lock()
            .map_err(|_| "operator registry poisoned")?
            .get(&operator_session)
            .ok_or(NO_OPERATOR)?;
        let socket = requester
            .ok_or("missing closure requester")?
            .try_clone()
            .map_err(|e| e.to_string())?;
        operators
            .closure_requests
            .lock()
            .map_err(|_| "closure registry poisoned")?
            .insert(request.id.clone(), (socket, owner));
    }
    let (reply, answer) = mpsc::channel();
    operator
        .send(Job {
            request: request.clone(),
            reply,
        })
        .map_err(|_| NO_OPERATOR.to_owned())?;
    let deadline = Instant::now() + ANSWER_TIMEOUT + Duration::from_secs(10);
    loop {
        match answer.recv_timeout(POLL.min(deadline.saturating_duration_since(Instant::now()))) {
            Ok(answer) => return answer,
            Err(RecvTimeoutError::Disconnected) => {
                return Err("the nix-secrets TUI disconnected".into());
            }
            Err(RecvTimeoutError::Timeout) => {
                if requester.is_some_and(peer_done) {
                    return Err("artifact signing requester disconnected".into());
                }
                if Instant::now() >= deadline {
                    return Err("the nix-secrets TUI did not answer in time".into());
                }
            }
        }
    }
}

pub(super) fn request_signature(
    stream: &mut UnixStream,
    operators: &Operators,
    peer: u32,
    request: crate::ssh_auth::SignatureRequest,
    reason: Option<String>,
) -> io::Result<()> {
    let result = request
        .validate()
        .and_then(|()| {
            request_operator(
                operators,
                peer,
                Vec::new(),
                reason,
                Some(request),
                None,
                None,
                None,
            )
        })
        .and_then(|answer| match answer {
            SecretAnswer::Signed { reply } => {
                crate::ssh_auth::validate_reply(&reply)?;
                Ok(reply)
            }
            SecretAnswer::Denied { reason } => Err(reason),
            SecretAnswer::Approved { .. }
            | SecretAnswer::ArtifactsSigned { .. }
            | SecretAnswer::ClosureSigned { .. } => {
                Err("the TUI returned an unasked answer".into())
            }
        });
    write_json(
        stream,
        &match result {
            Ok(reply) => Response::SshSignature { reply },
            Err(message) => Response::Error { message },
        },
    )
}

fn open_artifacts(
    request: &crate::artifact_signing::SigningRequest,
) -> Result<BTreeMap<String, std::fs::File>, String> {
    use std::os::unix::fs::MetadataExt;
    request.validate()?;
    let store_uid = std::fs::metadata("/nix/store")
        .map_err(|e| e.to_string())?
        .uid();
    let mut files = BTreeMap::new();
    for artifact in &request.manifest.artifacts {
        let canonical = std::fs::canonicalize(&artifact.path).map_err(|e| e.to_string())?;
        if !canonical.starts_with("/nix/store") {
            return Err("artifact escaped immutable Nix store".into());
        }
        let file = std::fs::File::open(canonical).map_err(|e| e.to_string())?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.mode() & 0o222 != 0
            || metadata.uid() != store_uid
            || metadata.len() != artifact.size
        {
            return Err("artifact is mutable or has changed size".into());
        }
        files.insert(artifact.role.clone(), file);
    }
    Ok(files)
}

pub(super) fn read_artifact(
    operators: &Operators,
    request_id: &str,
    role: &str,
    offset: u64,
) -> Result<Response, String> {
    use std::os::unix::fs::FileExt;
    let registry = operators
        .artifacts
        .lock()
        .map_err(|_| "artifact registry poisoned")?;
    let file = registry
        .get(request_id)
        .and_then(|files| files.get(role))
        .ok_or("no matching pending signing artifact")?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    if offset >= size {
        return Err("artifact offset outside file".into());
    }
    let mut buffer = vec![0; crate::artifact_signing::CHUNK_BYTES.min((size - offset) as usize)];
    file.read_exact_at(&mut buffer, offset)
        .map_err(|e| e.to_string())?;
    Ok(Response::SigningArtifactChunk {
        offset,
        bytes_base64: STANDARD.encode(buffer),
    })
}

pub(super) fn request_artifacts(
    stream: &mut UnixStream,
    operators: &Operators,
    peer: u32,
    request: crate::artifact_signing::SigningRequest,
    reason: Option<String>,
    schema: &crate::Schema,
) -> io::Result<()> {
    let result = (|| {
        request.validate()?;
        let path = SecretPath::parse(&request.identifier).map_err(|e| e.to_string())?;
        match schema.leaf(&path).map_err(|e| e.to_string())? {
            crate::LeafSpec::Operator(spec) if spec.signing_only => {}
            _ => return Err("artifact signing requires a signing-only operator key".into()),
        }
        let answer = request_operator(
            operators,
            peer,
            vec![request.identifier.clone()],
            reason,
            None,
            Some(request.clone()),
            None,
            Some(stream),
        )?;
        match answer {
            SecretAnswer::ArtifactsSigned { signatures } => {
                signatures.validate(&request.manifest)?;
                Ok(signatures)
            }
            SecretAnswer::Denied { reason } => Err(reason),
            _ => Err("the TUI returned an unasked answer".into()),
        }
    })();
    write_json(
        stream,
        &match result {
            Ok(signatures) => Response::ArtifactSignatures { signatures },
            Err(message) => Response::Error { message },
        },
    )
}

#[cfg(test)]
mod tests;

pub(super) fn request_closure(
    stream: &mut UnixStream,
    operators: &Operators,
    peer: u32,
    request: crate::closure_signing::SigningRequest,
    reason: Option<String>,
    schema: &crate::Schema,
    store: &crate::SecretStore,
) -> io::Result<()> {
    let result = (|| {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use sha2::{Digest, Sha256};
        request.validate()?;
        let path = SecretPath::parse(&request.identifier).map_err(|e| e.to_string())?;
        match schema.leaf(&path).map_err(|e| e.to_string())? {
            crate::LeafSpec::Operator(spec) if spec.signing_only => {}
            _ => return Err("closure signing requires a signing-only operator key".into()),
        }
        let record = store
            .get(&path)
            .map_err(|e| e.to_string())?
            .ok_or("missing closure signing record")?;
        let public = STANDARD
            .decode(
                record
                    .public_key
                    .ok_or("missing closure signing public key")?,
            )
            .map_err(|_| "invalid public key envelope")?;
        let text = std::str::from_utf8(&public).map_err(|_| "invalid public key envelope")?;
        crate::closure_signing::validate_public_key(text.strip_suffix('\n').unwrap_or(text))?;
        let fingerprint = format!("{:x}", Sha256::digest(&public));
        if request.public_key_sha256 != fingerprint {
            return Err("closure signing public key changed".into());
        }
        let answer = request_operator(
            operators,
            peer,
            vec![request.identifier.clone()],
            reason,
            None,
            None,
            Some(request.clone()),
            Some(stream),
        )?;
        let signatures = closure_answer(answer, &request.manifest)?;
        let name = text.split_once(':').ok_or("invalid public key envelope")?.0;
        if signatures
            .signatures
            .iter()
            .any(|s| s.signature.split_once(':').map(|(n, _)| n) != Some(name))
        {
            return Err("closure signature key name differs from approved public key".into());
        }
        Ok(signatures)
    })();
    write_json(
        stream,
        &match result {
            Ok(signatures) => Response::ClosureSignatures { signatures },
            Err(message) => Response::Error { message },
        },
    )
}

pub(super) fn check_closure(
    operators: &Operators,
    id: &str,
    peer: u32,
) -> Result<Response, String> {
    let mut pending = operators
        .closure_requests
        .lock()
        .map_err(|_| "closure registry poisoned")?;
    let (socket, owner) = pending
        .get(id)
        .ok_or("no matching pending closure request")?;
    if *owner != peer {
        return Err("closure request belongs to another operator".into());
    }
    if peer_done(socket) {
        pending.remove(id);
        return Err("closure signing requester disconnected".into());
    }
    Ok(Response::Success)
}

fn closure_answer(
    answer: SecretAnswer,
    manifest: &crate::closure_signing::Manifest,
) -> Result<crate::closure_signing::Signatures, String> {
    match answer {
        SecretAnswer::ClosureSigned { signatures } => {
            signatures.validate(manifest)?;
            Ok(signatures)
        }
        SecretAnswer::Denied { reason } => Err(reason),
        _ => Err("the TUI returned an unasked answer".into()),
    }
}
