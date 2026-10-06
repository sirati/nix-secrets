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
//!
//! The operator channel carries several requests at once, one per waiting
//! requester, each answered by its id whenever the operator decides. A
//! request that belongs to a procedure (see [`crate::procedure`]) carries
//! its step. Only a request without a procedure or the first step of one
//! has a deadline; the operator can cancel it, and the backend then waits
//! without one and tells a requester that asked for progress.
use super::{Request, Response};
use crate::SecretPath;
use crate::framing::{read_json, read_json_sensitive, write_json};
use crate::private_socket::runtime_directory;
use crate::procedure::ProcedureStep;
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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How long the backend waits for the operator on a request that counts
/// down. The TUI denies on its own after 120 seconds without a decision;
/// this bounds a TUI that stopped answering, including the time a 1Password
/// prompt may take after approval. Requests without a countdown, and those
/// whose countdown the operator cancelled, wait until answered or until the
/// TUI or the requester disconnects.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(600);
/// Grace after [`ANSWER_TIMEOUT`] for the TUI's own denial to arrive.
const ANSWER_GRACE: Duration = Duration::from_secs(10);
const HEARTBEAT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_secs(1);
/// How often a request without a TUI looks for one.
const ATTACH_POLL: Duration = Duration::from_millis(100);
/// Requests waiting for the operator at once, over all requesters.
pub const MAX_PENDING: usize = 16;

pub const NO_OPERATOR: &str =
    "no nix-secrets TUI is attached to this backend; open the nix-secrets TUI and retry";

/// What the operator channel delivers to a waiting request.
pub(super) enum Outcome {
    Answer(Result<SecretAnswer, String>),
    /// The operator cancelled the automatic denial.
    CountdownCancelled,
}

pub(super) struct Job {
    pub(super) request: SecretRequest,
    pub(super) reply: Sender<Outcome>,
}

/// What an attached TUI's connection handles, in arrival order.
pub(super) enum Inbox {
    Job(Job),
    /// The request no longer waits; tell the TUI to drop it.
    Withdraw(String),
    Step(ProcedureStep),
    Ended(String),
    /// From the TUI.
    Answer {
        request_id: String,
        answer: SecretAnswer,
    },
    /// From the TUI.
    CancelCountdown {
        request_id: String,
    },
    /// The TUI hung up or broke the protocol.
    Closed,
}

pub(super) struct Operators {
    pub(super) closure_requests: Mutex<BTreeMap<String, (UnixStream, u32)>>,
    pub(super) operator_peers: Mutex<BTreeMap<u64, u32>>,
    pub(super) artifacts: Mutex<BTreeMap<String, BTreeMap<String, std::fs::File>>>,
    /// Attached TUIs in attach order; the last one receives requests.
    pub(super) attached: Mutex<Vec<(u64, Sender<Inbox>)>>,
    /// How many requests wait for the operator.
    pending: AtomicUsize,
    next_request: AtomicU64,
    pub(super) procedures: super::procedures::Procedures,
    /// How long a request with a countdown may wait for its answer.
    deadline: Duration,
    /// How often idle connections get a heartbeat.
    heartbeat: Duration,
}

impl Default for Operators {
    fn default() -> Self {
        Self {
            closure_requests: Default::default(),
            operator_peers: Default::default(),
            artifacts: Default::default(),
            attached: Default::default(),
            pending: AtomicUsize::new(0),
            next_request: AtomicU64::new(0),
            procedures: Default::default(),
            deadline: ANSWER_TIMEOUT + ANSWER_GRACE,
            heartbeat: HEARTBEAT,
        }
    }
}

/// Releases one pending-request slot.
struct Pending<'a>(&'a AtomicUsize);

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Who asked, beyond the process: its connection, its procedure token and
/// whether it reads progress frames.
#[derive(Clone, Copy, Default)]
pub(super) struct Requester<'a> {
    pub(super) stream: Option<&'a UnixStream>,
    pub(super) procedure: Option<&'a str>,
    pub(super) progress: bool,
}

impl<'a> Requester<'a> {
    pub(super) fn new(stream: &'a UnixStream, procedure: Option<&'a str>, progress: bool) -> Self {
        Self {
            stream: Some(stream),
            procedure,
            progress,
        }
    }
}

impl Operators {
    /// Changes how long a request with a countdown waits for the operator
    /// and how often idle connections get a heartbeat.
    pub(super) fn with_timing(mut self, deadline: Duration, heartbeat: Duration) -> Self {
        self.deadline = deadline;
        self.heartbeat = heartbeat;
        self
    }

    fn claim(&self) -> Result<Pending<'_>, String> {
        self.pending
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |pending| {
                (pending < MAX_PENDING).then_some(pending + 1)
            })
            .map(|_| Pending(&self.pending))
            .map_err(|_| {
                format!(
                    "{MAX_PENDING} requests are already waiting for the operator; retry when one \
                     is answered"
                )
            })
    }

    pub(super) fn pending_count(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }

    /// Whether the TUI of this operator session is still attached.
    fn is_attached(&self, session: u64) -> bool {
        self.attached
            .lock()
            .is_ok_and(|attached| attached.iter().any(|(id, _)| *id == session))
    }

    /// Forgets an operator session whose connection is gone.
    fn detach(&self, session: u64) {
        if let Ok(mut attached) = self.attached.lock() {
            attached.retain(|(id, _)| *id != session);
        }
    }

    fn latest(&self) -> Option<(u64, Sender<Inbox>)> {
        self.attached
            .lock()
            .ok()?
            .last()
            .map(|(id, sender)| (*id, sender.clone()))
    }

    fn broadcast(&self, message: impl Fn() -> Inbox) {
        if let Ok(attached) = self.attached.lock() {
            for (_, sender) in attached.iter() {
                let _ = sender.send(message());
            }
        }
    }

    pub(super) fn broadcast_step(&self, step: ProcedureStep) {
        self.broadcast(|| Inbox::Step(step.clone()));
    }

    pub(super) fn broadcast_end(&self, id: &str) {
        self.broadcast(|| Inbox::Ended(id.to_owned()));
    }

    /// Verifies a procedure token for `peer`, numbers the next step and
    /// tells the TUIs.
    pub(super) fn advance(
        &self,
        token: &str,
        peer: u32,
        label: &str,
        deployment: bool,
    ) -> Result<ProcedureStep, String> {
        let step = self.procedures.next_step(token, peer, label, deployment)?;
        self.broadcast_step(step.clone());
        Ok(step)
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
    let (sender, inbox) = mpsc::channel::<Inbox>();
    // Answers and cancellations arrive at any time, so a reader thread
    // turns them into inbox messages next to the jobs.
    let mut reader = stream.try_clone()?;
    let from_tui = sender.clone();
    let reading = std::thread::spawn(move || {
        loop {
            let message = match read_json_sensitive::<Request>(&mut reader) {
                Ok(Some(Request::AnswerSecretRequest { request_id, answer })) => {
                    Inbox::Answer { request_id, answer }
                }
                Ok(Some(Request::CancelCountdown { request_id })) => {
                    Inbox::CancelCountdown { request_id }
                }
                _ => Inbox::Closed,
            };
            let closed = matches!(message, Inbox::Closed);
            if from_tui.send(message).is_err() || closed {
                return;
            }
        }
    });
    operators
        .attached
        .lock()
        .map_err(|_| io::Error::other("operator registry lock is poisoned"))?
        .push((session, sender));
    // Requests sent to this TUI and not yet answered, by id.
    let mut waiting: BTreeMap<String, Sender<Outcome>> = BTreeMap::new();
    let result = (|| -> io::Result<()> {
        write_json(stream, &Response::OperatorAttached)?;
        for procedure in operators.procedures.snapshot() {
            write_json(stream, &Response::ProcedureUpdate { procedure })?;
        }
        let mut last_heartbeat = Instant::now();
        loop {
            let wait = operators.heartbeat.saturating_sub(last_heartbeat.elapsed());
            match inbox.recv_timeout(wait) {
                Ok(Inbox::Job(job)) => {
                    write_json(
                        stream,
                        &Response::SecretRequested {
                            request: job.request.clone(),
                        },
                    )?;
                    waiting.insert(job.request.id.clone(), job.reply);
                }
                Ok(Inbox::Withdraw(request_id)) => {
                    if waiting.remove(&request_id).is_some() {
                        write_json(stream, &Response::SecretRequestWithdrawn { request_id })?;
                    }
                }
                Ok(Inbox::Step(procedure)) => {
                    write_json(stream, &Response::ProcedureUpdate { procedure })?
                }
                Ok(Inbox::Ended(id)) => write_json(stream, &Response::ProcedureEnded { id })?,
                // An answer counts once, for a request still waiting. A late
                // answer to a withdrawn request, a replay or a made-up id
                // reaches nobody.
                Ok(Inbox::Answer { request_id, answer }) => {
                    if let Some(reply) = waiting.remove(&request_id) {
                        if let Ok(mut requests) = operators.closure_requests.lock() {
                            requests.remove(&request_id);
                        }
                        let _ = reply.send(Outcome::Answer(Ok(answer)));
                    }
                }
                Ok(Inbox::CancelCountdown { request_id }) => {
                    if let Some(reply) = waiting.get(&request_id) {
                        let _ = reply.send(Outcome::CountdownCancelled);
                    }
                }
                Ok(Inbox::Closed) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
                Err(RecvTimeoutError::Timeout) => {
                    write_json(stream, &Response::Heartbeat)?;
                    last_heartbeat = Instant::now();
                }
            }
        }
    })();
    if let Ok(mut attached) = operators.attached.lock() {
        attached.retain(|(id, _)| *id != session);
    }
    if let Ok(mut peers) = operators.operator_peers.lock() {
        peers.remove(&session);
    }
    // Waiting requesters learn that this TUI is gone.
    drop(waiting);
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let _ = reading.join();
    result
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
    procedure: Option<String>,
    progress: bool,
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
    let values = match approved_values(
        operators,
        peer,
        identifiers,
        reason,
        Requester::new(stream, procedure.as_deref(), progress),
    ) {
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
    requester: Requester<'_>,
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
    let answer = request_operator(
        operators,
        peer,
        identifiers,
        reason,
        None,
        None,
        None,
        requester,
    )?;
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

/// What a request asks for, as a procedure step label.
fn step_label(
    identifiers: &[String],
    ssh_signature: Option<&crate::ssh_auth::SignatureRequest>,
    artifact_signature: Option<&crate::artifact_signing::SigningRequest>,
    closure_signature: Option<&crate::closure_signing::SigningRequest>,
) -> String {
    if let Some(signing) = closure_signature {
        format!("sign closure for {}", signing.host)
    } else if let Some(signing) = artifact_signature {
        format!("sign artifacts for {}", signing.host)
    } else if let Some(signature) = ssh_signature {
        format!("SSH authentication to {}", signature.destination)
    } else {
        format!(
            "release {} secret value{}",
            identifiers.len(),
            if identifiers.len() == 1 { "" } else { "s" }
        )
    }
}

fn request_operator(
    operators: &Operators,
    peer: u32,
    identifiers: Vec<String>,
    reason: Option<String>,
    ssh_signature: Option<crate::ssh_auth::SignatureRequest>,
    artifact_signature: Option<crate::artifact_signing::SigningRequest>,
    closure_signature: Option<crate::closure_signing::SigningRequest>,
    requester: Requester<'_>,
) -> Result<SecretAnswer, String> {
    if reason
        .as_ref()
        .is_some_and(|r| r.len() > crate::secret_request::MAX_REQUEST_REASON_BYTES)
    {
        return Err("request reason exceeds 4096 bytes".into());
    }
    let _pending = operators.claim()?;
    // Without an attached TUI the request waits for one; nothing counts
    // down meanwhile.
    let (operator_session, operator) = wait_for_operator(operators, requester, &mut true)?;
    // Checked and numbered only once a TUI can be asked, so a refusal never
    // uses up a step.
    let procedure = requester
        .procedure
        .map(|token| {
            let label = step_label(
                &identifiers,
                ssh_signature.as_ref(),
                artifact_signature.as_ref(),
                closure_signature.as_ref(),
            );
            operators.advance(token, peer, &label, false)
        })
        .transpose()?;
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
        procedure,
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
    let id = request.id.clone();
    let (reply, answer) = mpsc::channel();
    let mut operator = operator;
    let mut operator_session = operator_session;
    loop {
        if request.closure_signature.is_some() {
            let owner = *operators
                .operator_peers
                .lock()
                .map_err(|_| "operator registry poisoned")?
                .get(&operator_session)
                .ok_or(NO_OPERATOR)?;
            let socket = requester
                .stream
                .ok_or("missing closure requester")?
                .try_clone()
                .map_err(|e| e.to_string())?;
            operators
                .closure_requests
                .lock()
                .map_err(|_| "closure registry poisoned")?
                .insert(request.id.clone(), (socket, owner));
        }
        // The countdown starts when a TUI receives the request, not while it
        // waits for one.
        let deadline = request
            .countdown()
            .then(|| Instant::now() + operators.deadline);
        let job = Job {
            request: request.clone(),
            reply: reply.clone(),
        };
        if operator.send(Inbox::Job(job)).is_ok() {
            match wait_for_answer(operators, operator_session, &operator, &id, &answer, requester, deadline)? {
                Some(answer) => return Ok(answer),
                None => {}
            }
        } else {
            operators.detach(operator_session);
        }
        // That TUI went away before answering. The request waits for the
        // next one, which shows it again from the start.
        (operator_session, operator) = wait_for_operator(operators, requester, &mut true)?;
    }
}

/// Waits until a TUI is attached. A requester that reads progress is told
/// once (`announce`) and gets heartbeats; one that leaves ends the wait.
fn wait_for_operator(
    operators: &Operators,
    requester: Requester<'_>,
    announce: &mut bool,
) -> Result<(u64, Sender<Inbox>), String> {
    let mut last_heartbeat = Instant::now();
    loop {
        if let Some(operator) = operators.latest() {
            return Ok(operator);
        }
        if requester.stream.is_some_and(peer_done) {
            return Err("the requester disconnected".into());
        }
        if let Some(stream) = requester.stream.filter(|_| requester.progress) {
            let frame = if std::mem::take(announce) {
                Some(Response::WaitingForOperator)
            } else if last_heartbeat.elapsed() >= operators.heartbeat {
                Some(Response::Heartbeat)
            } else {
                None
            };
            if let Some(frame) = frame {
                write_json(&mut &*stream, &frame)
                    .map_err(|_| "the requester disconnected".to_owned())?;
                last_heartbeat = Instant::now();
            }
        }
        std::thread::sleep(ATTACH_POLL);
    }
}

/// Waits for the operator's answer to the request `id` sent to `operator`.
/// `None` means that TUI went away without answering.
fn wait_for_answer(
    operators: &Operators,
    operator_session: u64,
    operator: &Sender<Inbox>,
    id: &str,
    answer: &mpsc::Receiver<Outcome>,
    requester: Requester<'_>,
    mut deadline: Option<Instant>,
) -> Result<Option<SecretAnswer>, String> {
    // The TUI drops a request that no longer waits.
    let withdraw = |reason: &str| {
        let _ = operator.send(Inbox::Withdraw(id.to_owned()));
        Err(reason.to_owned())
    };
    let mut last_heartbeat = Instant::now();
    loop {
        let poll = deadline.map_or(POLL, |deadline| {
            POLL.min(deadline.saturating_duration_since(Instant::now()))
        });
        match answer.recv_timeout(poll) {
            Ok(Outcome::Answer(answer)) => return answer.map(Some),
            Ok(Outcome::CountdownCancelled) => {
                deadline = None;
                if let Some(stream) = requester.stream.filter(|_| requester.progress) {
                    if write_json(&mut &*stream, &Response::CountdownCancelled).is_err() {
                        return withdraw("the requester disconnected");
                    }
                }
            }
            // Only this function holds a sender besides the TUI's, so the
            // channel never disconnects; a TUI that went away is noticed
            // through the operator registry instead.
            Err(RecvTimeoutError::Disconnected) => return Ok(None),
            Err(RecvTimeoutError::Timeout) => {
                if !operators.is_attached(operator_session) {
                    return Ok(None);
                }
                if requester.stream.is_some_and(peer_done) {
                    return withdraw("the requester disconnected");
                }
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return withdraw("the nix-secrets TUI did not answer in time");
                }
                if let Some(stream) = requester.stream.filter(|_| requester.progress) {
                    if last_heartbeat.elapsed() >= operators.heartbeat {
                        if write_json(&mut &*stream, &Response::Heartbeat).is_err() {
                            return withdraw("the requester disconnected");
                        }
                        last_heartbeat = Instant::now();
                    }
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
    procedure: Option<String>,
    progress: bool,
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
                Requester::new(stream, procedure.as_deref(), progress),
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
    procedure: Option<String>,
    progress: bool,
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
            Requester::new(stream, procedure.as_deref(), progress),
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
    procedure: Option<String>,
    progress: bool,
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
            Requester::new(stream, procedure.as_deref(), progress),
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
