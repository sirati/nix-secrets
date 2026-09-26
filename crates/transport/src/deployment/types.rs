use crate::{FrameError, SshError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::{fmt, io};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const STORAGE_BOX_SSH_KEY: &str = "storage-box-ssh-key";
pub const LOCAL_SSH_KEY: &str = "local-ssh-key";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub path: String,
    pub category: String,
    pub owner: String,
    pub group: String,
    pub mode: String,
    #[serde(default)]
    pub consumer_units: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBoxBootstrap {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub host_public_keys: Vec<String>,
    #[serde(default)]
    pub known_hosts_file: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSecret {
    pub identifier: String,
    pub recipient_ids: Vec<String>,
    pub destination: Destination,
    #[serde(default)]
    pub public_info: Option<PublicInfoAttestation>,
    pub current_version_id: Option<String>,
    /// Canonical JSON of the generator the target would use for this value
    /// when asked to generate it. Absent when the value must be supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generator: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetTask {
    pub identifier: String,
    #[serde(rename = "type")]
    pub task_type: String,
    pub recipient_ids: Vec<String>,
    pub output: Destination,
    pub bootstrap: Option<StorageBoxBootstrap>,
    pub current_version_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetState {
    pub protocol_version: u16,
    pub hostname: String,
    pub secrets: Vec<TargetSecret>,
    #[serde(default)]
    pub tasks: Vec<TargetTask>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedSecret {
    pub identifier: String,
    pub recipient_ids: Vec<String>,
    pub destination: Destination,
    pub public_info: Option<PublicInfoAttestation>,
    pub generator: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicInfoAttestation {
    pub shared_id: String,
    pub expected_ssh_host: String,
    pub expected_ssh_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedTask {
    pub identifier: String,
    pub task_type: String,
    pub recipient_ids: Vec<String>,
    pub output: Destination,
    pub bootstrap: Option<StorageBoxBootstrap>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedTarget {
    pub hostname: String,
    pub secrets: Vec<ExpectedSecret>,
    pub tasks: Vec<ExpectedTask>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSelection {
    pub identifiers: Vec<String>,
    #[serde(default)]
    pub task_identifiers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DeployEntry {
    pub identifier: String,
    pub version_id: String,
    pub contents_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct TaskEntry {
    pub identifier: String,
    pub version_id: String,
    pub password_base64: String,
    pub client_contribution_base64: String,
}

/// Asks the target to generate an unset value locally, or to adopt the value
/// it already has installed, and to return only its ciphertext.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct GenerateEntry {
    pub identifier: String,
    pub client_contribution_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DeploymentBatch {
    pub version: u16,
    /// Identifiers of both supplied `entries` and target-generated values.
    pub requested_identifiers: Vec<String>,
    pub entries: Vec<DeployEntry>,
    #[serde(default)]
    pub requested_tasks: Vec<String>,
    #[serde(default)]
    pub tasks: Vec<TaskEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generate: Vec<GenerateEntry>,
}

/// An age-encrypted value generated on the target. The plaintext never
/// leaves the target; this record is stored verbatim in the operator store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedRecord {
    pub format_version: u16,
    pub version_id_base64: String,
    pub recipient_ids: Vec<String>,
    pub age_ciphertext_base64: String,
    /// The target already had this value installed and re-encrypted it.
    pub adopted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DeploymentResult {
    Applied {
        versions: BTreeMap<String, String>,
        #[serde(default)]
        generated_public_keys: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        generated_records: BTreeMap<String, GeneratedRecord>,
    },
    Rejected {
        message: String,
    },
}

/// What a target reports after applying a batch.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppliedOutput {
    pub versions: BTreeMap<String, String>,
    pub generated_public_keys: BTreeMap<String, String>,
    pub generated_records: BTreeMap<String, GeneratedRecord>,
}

#[derive(Debug)]
pub enum DeploymentError {
    Ssh(SshError),
    Protocol(FrameError),
    Json(serde_json::Error),
    Io(io::Error),
    Invalid(&'static str),
    Rejected,
}

impl fmt::Display for DeploymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssh(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
            Self::Json(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
            Self::Io(error) => error.fmt(f),
            Self::Rejected => f.write_str("target rejected deployment"),
        }
    }
}

impl std::error::Error for DeploymentError {}
impl From<SshError> for DeploymentError {
    fn from(v: SshError) -> Self {
        Self::Ssh(v)
    }
}
impl From<FrameError> for DeploymentError {
    fn from(v: FrameError) -> Self {
        Self::Protocol(v)
    }
}
impl From<serde_json::Error> for DeploymentError {
    fn from(v: serde_json::Error) -> Self {
        Self::Json(v)
    }
}
impl From<io::Error> for DeploymentError {
    fn from(v: io::Error) -> Self {
        Self::Io(v)
    }
}
