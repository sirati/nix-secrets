use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DeploymentBatch {
    pub version: u32,
    pub requested_identifiers: Vec<String>,
    pub entries: Vec<SecretDeployment>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct SecretDeployment {
    pub identifier: String,
    pub version_id: String,
    pub contents_base64: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ResolvedBatch {
    pub(crate) entries: Vec<ResolvedSecret>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct ResolvedSecret {
    pub identifier: String,
    pub version_id: String,
    pub service: String,
    pub class: SecretClass,
    pub secret: String,
    pub contents: Vec<u8>,
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretClass {
    Setup,
    Service,
    Backup,
}

impl SecretClass {
    pub(crate) fn directory(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Service => "service",
            Self::Backup => "backup",
        }
    }
}
