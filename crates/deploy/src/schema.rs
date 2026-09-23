use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

pub struct AuditDetail {
    pub ssh_user: Option<String>,
    pub key_names: Vec<String>,
}

impl ResolvedBatch {
    pub fn audit_details(&self) -> BTreeMap<String, AuditDetail> {
        self.entries
            .iter()
            .map(|entry| {
                (
                    entry.identifier.clone(),
                    AuditDetail {
                        ssh_user: entry.audit_ssh_user.clone(),
                        key_names: entry.audit_key_names.clone(),
                    },
                )
            })
            .collect()
    }
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
    pub audit_ssh_user: Option<String>,
    pub audit_key_names: Vec<String>,
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
