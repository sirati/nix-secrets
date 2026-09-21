use serde::{Deserialize, Serialize};

pub const MAX_REQUEST_ID: usize = 128;
pub const MAX_APPROVAL_ITEMS: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub id: String,
    pub target: String,
    pub secrets: Vec<String>,
}

impl ApprovalRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.is_empty() || self.id.len() > MAX_REQUEST_ID {
            return Err("request id has an invalid length");
        }
        if !self
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
        {
            return Err("request id contains invalid characters");
        }
        if self.target.is_empty() || self.target.len() > 512 {
            return Err("target has an invalid length");
        }
        if self.secrets.is_empty() || self.secrets.len() > MAX_APPROVAL_ITEMS {
            return Err("secret list has an invalid length");
        }
        if self
            .secrets
            .iter()
            .any(|item| item.is_empty() || item.len() > 1024)
        {
            return Err("secret identifier has an invalid length");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum ApprovalStatus {
    Pending,
    Claimed { lease_id: u64, expires_in_ms: u64 },
    Resolved { decision: Decision },
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    pub lease_id: u64,
    pub expires_in_ms: u64,
}
