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
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
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
}
