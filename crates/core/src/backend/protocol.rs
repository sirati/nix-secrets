use super::BackendEvent;
use crate::{ApprovalRequest, ApprovalStatus, Decision, EncryptedSecret, SecretPath};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Get {
        path: SecretPath,
    },
    /// Whether the stored record of `path` is committed in `HEAD`.
    CommitState {
        path: SecretPath,
    },
    List,
    Set {
        path: SecretPath,
        envelope: EncryptedSecret,
    },
    SetIfVersion {
        path: SecretPath,
        envelope: EncryptedSecret,
        expected_version: Option<Vec<u8>>,
    },
    Remove {
        path: SecretPath,
    },
    RemoveIfVersion {
        path: SecretPath,
        expected_version: Vec<u8>,
    },
    GetGeneratedPublicKey {
        path: SecretPath,
    },
    SetGeneratedPublicKeyIfVersion {
        path: SecretPath,
        value: crate::GeneratedPublicKey,
        expected_version: Option<String>,
    },
    SetPublicKeyIfVersion {
        path: SecretPath,
        public_key: String,
        expected_version: Vec<u8>,
        expected_public_key: Option<String>,
    },
    ListPublicInfo,
    GetPublicInfo {
        shared_id: String,
    },
    SetPublicInfoIfVersion {
        path: SecretPath,
        value: crate::PublicInfoRecord,
        expected_version: Option<String>,
    },
    RemovePublicInfoIfVersion {
        path: SecretPath,
        expected_version: String,
    },
    RegisterFrontend,
    PollApprovals,
    SubmitApproval {
        request: ApprovalRequest,
    },
    ClaimApproval {
        request_id: String,
        lease_ms: u64,
    },
    RenewApproval {
        request_id: String,
        lease_id: u64,
        lease_ms: u64,
    },
    ResolveApproval {
        request_id: String,
        lease_id: u64,
        decision: Decision,
        /// What the frontend did, for the requester: the deployment summary
        /// or why it refused.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    CancelApproval {
        request_id: String,
    },
    ApprovalStatus {
        request_id: String,
    },
    SubscribeChanges,
    ListProfiles,
    SaveProfile {
        name: String,
        profile: crate::ViewProfile,
        expected_revision: u64,
    },
    DeleteProfile {
        name: String,
        expected_revision: u64,
    },
    /// What a commit of the managed files would contain.
    CommitSummary,
    /// Commits the managed files. With `forward_agent`, the backend relays
    /// the signing agent's requests as [`Response::AgentRequest`] frames on
    /// this connection and waits for an [`Request::AgentReply`] to each.
    Commit {
        options: crate::git::CommitOptions,
        forward_agent: bool,
    },
    /// The frontend agent's reply to an [`Response::AgentRequest`].
    AgentReply {
        message: Vec<u8>,
    },
    /// Makes this connection the operator channel of a TUI. The backend
    /// answers [`Response::OperatorAttached`], then sends heartbeats and
    /// [`Response::SecretRequested`] frames, each answered by
    /// [`Request::AnswerSecretRequest`].
    AttachOperator,
    /// The TUI's answer to a [`Response::SecretRequested`]; carries the
    /// plaintexts when the operator approved.
    AnswerSecretRequest {
        request_id: String,
        answer: crate::secret_request::SecretAnswer,
    },
    /// Asks the attached TUI for these values. On approval the backend
    /// answers [`Response::SecretSession`] and serves the values on that
    /// socket until [`Request::EndSecretSession`] or a disconnect.
    RequestSecrets {
        identifiers: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// The token from [`crate::procedure::PROCEDURE_ENVIRONMENT`]: the
        /// request becomes the next step of that procedure.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        procedure: Option<String>,
        /// The requester reads [`Response::Heartbeat`] and
        /// [`Response::CountdownCancelled`] frames before the answer.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        progress: bool,
    },
    EndSecretSession,
    RequestSshSignature {
        request: crate::ssh_auth::SignatureRequest,
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        procedure: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        progress: bool,
    },
    RequestArtifactSignatures {
        request: crate::artifact_signing::SigningRequest,
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        procedure: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        progress: bool,
    },
    RequestClosureSignatures {
        request: crate::closure_signing::SigningRequest,
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        procedure: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        progress: bool,
    },
    CheckClosureSigningRequest {
        request_id: String,
    },
    ReadSigningArtifact {
        request_id: String,
        role: String,
        offset: u64,
    },
    /// Asks the registered frontends to deploy every deployable value of
    /// `target`. The backend builds the [`ApprovalRequest`] from its schema
    /// and answers [`Response::DeploymentRequested`]; the requester follows
    /// it with [`Request::ApprovalStatus`]. Without a registered frontend it
    /// fails with [`crate::backend::NO_OPERATOR`].
    RequestDeployment {
        target: String,
        #[serde(default)]
        allow_partial: bool,
        /// A procedure token: the deployment becomes its next step.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        procedure: Option<String>,
    },
    /// Registers a procedure owned by this connection's process; see
    /// [`crate::procedure`]. The backend answers
    /// [`Response::ProcedureBegun`] and the procedure lives until
    /// [`Request::EndProcedure`] or a disconnect.
    BeginProcedure {
        title: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        steps: Option<u32>,
    },
    EndProcedure,
    /// The schema document the backend evaluated; see
    /// [`Response::SchemaDocument`]. A TUI that finds requests waiting uses it
    /// instead of evaluating the repository again.
    GetSchema,
    /// On the operator channel: the operator stopped the automatic denial
    /// of this request. The backend drops its own deadline for it and tells
    /// the requester.
    CancelCountdown {
        request_id: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    Success,
    ArtifactSignatures {
        signatures: crate::artifact_signing::Signatures,
    },
    ClosureSignatures {
        signatures: crate::closure_signing::Signatures,
    },
    SigningArtifactChunk {
        offset: u64,
        bytes_base64: String,
    },
    Secret {
        envelope: Option<EncryptedSecret>,
    },
    Secrets {
        entries: std::collections::BTreeMap<String, EncryptedSecret>,
    },
    Updated,
    Removed {
        existed: bool,
    },
    GeneratedPublicKey {
        value: Option<crate::GeneratedPublicKey>,
    },
    PublicInfo {
        value: Option<crate::PublicInfoRecord>,
    },
    PublicInfoEntries {
        entries: std::collections::BTreeMap<String, crate::PublicInfoRecord>,
    },
    Error {
        message: String,
    },
    FrontendRegistered,
    Approvals {
        requests: Vec<ApprovalRequest>,
        /// The procedure step of each request that belongs to one, by
        /// request id. Only the backend assigns these; a submitted request
        /// never carries one.
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        procedures: std::collections::BTreeMap<String, crate::procedure::ProcedureStep>,
    },
    ApprovalState {
        state: ApprovalStatus,
    },
    ApprovalClaimed {
        lease_id: u64,
        expires_in_ms: u64,
    },
    ApprovalRenewed {
        expires_in_ms: u64,
    },
    ApprovalResolved,
    ApprovalCancelled,
    Subscribed,
    Change {
        update: BackendEvent,
    },
    Heartbeat,
    Profiles {
        snapshot: crate::ProfileSnapshot,
    },
    CommitState {
        state: crate::CommitState,
    },
    CommitSummary {
        summary: crate::git::CommitSummary,
    },
    /// An ssh-agent request from the commit's signing program.
    AgentRequest {
        message: Vec<u8>,
    },
    Committed {
        result: crate::git::CommitResult,
    },
    OperatorAttached,
    /// A process on the backend host asks for secrets; see
    /// [`Request::AttachOperator`].
    SecretRequested {
        request: crate::secret_request::SecretRequest,
    },
    /// The approved values are served on this private socket.
    SecretSession {
        socket: std::path::PathBuf,
    },
    SecretSessionEnded,
    SshSignature {
        reply: Vec<u8>,
    },
    /// The deployment request is queued for the frontends.
    DeploymentRequested {
        request: ApprovalRequest,
    },
    /// The evaluated schema document this backend started with, if it was
    /// given one, its age, and whether requests wait for an operator.
    SchemaDocument {
        json: Option<String>,
        age_ms: u64,
        waiting: bool,
    },
    /// The procedure is registered; `token` goes to the requesters in
    /// [`crate::procedure::PROCEDURE_ENVIRONMENT`].
    ProcedureBegun {
        id: String,
        token: String,
    },
    /// On the operator channel: a procedure started or reached a new step.
    ProcedureUpdate {
        procedure: crate::procedure::ProcedureStep,
    },
    /// On the operator channel, after the `ProcedureUpdate` of every live
    /// procedure at attach: their ids. A reattaching TUI drops the rest.
    ProceduresListed {
        ids: Vec<String>,
    },
    /// The procedure is over: on the operator channel, and as the answer to
    /// [`Request::EndProcedure`].
    ProcedureEnded {
        id: String,
    },
    /// On the operator channel: the request no longer waits, because its
    /// requester left or the backend gave up. A late answer is ignored.
    SecretRequestWithdrawn {
        request_id: String,
    },
    /// To a requester that asked for progress: no TUI is attached yet; the
    /// request waits for one, and nothing counts down meanwhile.
    WaitingForOperator,
    /// To a requester that asked for progress: the operator cancelled the
    /// automatic denial; the request now waits for the operator's decision.
    CountdownCancelled,
}
