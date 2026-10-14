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
    /// Keeps a value a host returned that the schema did not accept.
    Quarantine {
        value: crate::QuarantinedValue,
    },
    ListQuarantine,
    /// Removes a quarantined value the operator adopted or discarded.
    RemoveQuarantined {
        id: String,
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
        /// A login approval this connection got with
        /// [`Request::RequestSshLoginGrant`]. The TUI then signs without
        /// asking, if the approval still covers the login.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<String>,
    },
    /// Asks the operator to approve SSH logins before the requester
    /// connects. On approval the backend answers
    /// [`Response::SshLoginGranted`], and [`Request::RequestSshSignature`]
    /// on the same connection may name the grant.
    RequestSshLoginGrant {
        request: crate::ssh_auth::LoginGrantRequest,
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
    /// Ends the procedure of this connection. `exit_code` is how its command
    /// exited, as a shell reports it (128 + signal), if it is known.
    EndProcedure {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },
    /// From inside a procedure: the step `label` failed because of
    /// `reason`. The backend numbers it like a repeatable request, so a
    /// second report about the same step updates it, marks it failed in the
    /// [`Response::ProcedureUpdate`] it broadcasts and answers
    /// [`Response::Success`].
    FailProcedureStep {
        /// The token from [`crate::procedure::PROCEDURE_ENVIRONMENT`].
        procedure: String,
        label: String,
        reason: String,
    },
    /// From inside a procedure: the step `label` worked, with a caveat,
    /// `reason`. Numbered like [`Request::FailProcedureStep`]; it sets the
    /// step's warning and never touches its failure.
    WarnProcedureStep {
        /// The token from [`crate::procedure::PROCEDURE_ENVIRONMENT`].
        procedure: String,
        label: String,
        reason: String,
    },
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
    Quarantined {
        id: String,
    },
    QuarantineEntries {
        entries: std::collections::BTreeMap<String, crate::QuarantinedValue>,
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
    /// The operator approved the SSH logins. The grant lasts
    /// `expires_in_seconds` and covers `signatures` logins.
    SshLoginGranted {
        grant: String,
        expires_in_seconds: u64,
        signatures: u32,
    },
    /// The deployment request is queued for the frontends.
    DeploymentRequested {
        request: ApprovalRequest,
        /// No frontend is registered yet: the request waits in the queue,
        /// and nothing happens until a TUI claims it and its operator
        /// approves it.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        waiting_for_operator: bool,
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
    /// On the operator channel: the requester that holds this login
    /// approval disconnected. Its signer stops.
    SshLoginGrantEnded {
        grant: String,
    },
    /// The procedure is over: on the operator channel, and as the answer to
    /// [`Request::EndProcedure`].
    ProcedureEnded {
        id: String,
        /// How its command exited, if `EndProcedure` said so.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procedure::ProcedureStep;

    #[test]
    fn a_failed_step_report_and_its_update_round_trip() {
        let request = Request::FailProcedureStep {
            procedure: "proc-1-ab:secret".into(),
            label: "activate ns1".into(),
            reason: "rolled back".into(),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"operation": "fail-procedure-step",
                "procedure": "proc-1-ab:secret", "label": "activate ns1",
                "reason": "rolled back"})
        );
        match serde_json::from_value::<Request>(json).unwrap() {
            Request::FailProcedureStep { procedure, label, reason } => {
                assert_eq!(
                    (procedure.as_str(), label.as_str(), reason.as_str()),
                    ("proc-1-ab:secret", "activate ns1", "rolled back")
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        let mut step = ProcedureStep {
            id: "proc-1-ab".into(),
            title: "Update ns1".into(),
            step: 2,
            steps: Some(4),
            label: "activate ns1".into(),
            deployment: false,
            failure: Some("rolled back".into()),
            warning: None,
        };
        let update = serde_json::to_string(&Response::ProcedureUpdate {
            procedure: step.clone(),
        })
        .unwrap();
        assert!(update.contains(r#""failure":"rolled back""#), "{update}");
        match serde_json::from_str::<Response>(&update).unwrap() {
            Response::ProcedureUpdate { procedure } => assert_eq!(procedure, step),
            other => panic!("unexpected {other:?}"),
        }
        // A step without failure keeps the old wire format.
        step.failure = None;
        let update = serde_json::to_string(&Response::ProcedureUpdate {
            procedure: step.clone(),
        })
        .unwrap();
        assert!(!update.contains("failure"), "{update}");
        // Unknown fields are still refused.
        assert!(serde_json::from_str::<ProcedureStep>(
            r#"{"id":"p","title":"t","step":1,"label":"l","failed":true}"#
        )
        .is_err());
    }

    #[test]
    fn a_warned_step_report_and_its_update_round_trip() {
        let request = Request::WarnProcedureStep {
            procedure: "proc-1-ab:secret".into(),
            label: "activate ns1".into(),
            reason: "nothing regressed".into(),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"operation": "warn-procedure-step",
                "procedure": "proc-1-ab:secret", "label": "activate ns1",
                "reason": "nothing regressed"})
        );
        match serde_json::from_value::<Request>(json).unwrap() {
            Request::WarnProcedureStep { procedure, label, reason } => {
                assert_eq!(
                    (procedure.as_str(), label.as_str(), reason.as_str()),
                    ("proc-1-ab:secret", "activate ns1", "nothing regressed")
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        let mut step = ProcedureStep {
            id: "proc-1-ab".into(),
            title: "Update ns1".into(),
            step: 2,
            steps: Some(4),
            label: "activate ns1".into(),
            deployment: false,
            failure: None,
            warning: Some("nothing regressed".into()),
        };
        let update = serde_json::to_string(&Response::ProcedureUpdate {
            procedure: step.clone(),
        })
        .unwrap();
        assert!(update.contains(r#""warning":"nothing regressed""#), "{update}");
        assert!(!update.contains("failure"), "{update}");
        match serde_json::from_str::<Response>(&update).unwrap() {
            Response::ProcedureUpdate { procedure } => assert_eq!(procedure, step),
            other => panic!("unexpected {other:?}"),
        }
        step.warning = None;
        let update = serde_json::to_string(&Response::ProcedureUpdate {
            procedure: step.clone(),
        })
        .unwrap();
        assert!(!update.contains("warning"), "{update}");
    }
}
