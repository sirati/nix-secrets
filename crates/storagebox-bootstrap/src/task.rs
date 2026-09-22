use crate::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StorageBoxTask {
    pub schema_version: u8,
    pub task_id: String,
    pub target_hostname: String,
    pub storage_box_host: String,
    pub storage_box_user: String,
    pub port: u16,
    pub pinned_host_keys: Vec<String>,
    pub output: Output,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Output {
    pub path: String,
    pub owner: String,
    pub group: String,
    pub mode: u32,
}

impl StorageBoxTask {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1 {
            return bad("unsupported schemaVersion");
        }
        token(&self.task_id, "taskId")?;
        dns_name(&self.target_hostname, "targetHostname")?;
        dns_name(&self.storage_box_host, "storageBoxHost")?;
        token(&self.storage_box_user, "storageBoxUser")?;
        if self.port != 23 {
            return bad("Storage Box SSH port must be 23");
        }
        if self.pinned_host_keys.is_empty() {
            return bad("pinnedHostKeys is empty");
        }
        let mut pins = HashSet::new();
        for pin in &self.pinned_host_keys {
            let fingerprint = validate_pin(pin)?;
            if !pins.insert(fingerprint) {
                return bad("pinnedHostKeys contains duplicate keys");
            }
        }
        let path = Path::new(&self.output.path);
        if !path.is_absolute() || self.output.path.contains('\0') {
            return bad("output path must be absolute");
        }
        token(&self.output.owner, "output owner")?;
        token(&self.output.group, "output group")?;
        if !matches!(self.output.mode, 0o400 | 0o440) {
            return bad("output mode must be 0400 or 0440");
        }
        Ok(())
    }

    pub fn marker_prefix(&self) -> String {
        format!("nix-secrets:{}:{}:", self.target_hostname, self.task_id)
    }
}

fn token(value: &str, field: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return bad(&format!("{field} contains invalid characters"));
    }
    Ok(())
}

fn dns_name(value: &str, field: &str) -> Result<(), Error> {
    token(value, field)?;
    if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return bad(&format!("{field} is not a DNS name"));
    }
    Ok(())
}

fn validate_pin(pin: &str) -> Result<String, Error> {
    let fields: Vec<_> = pin.split_ascii_whitespace().collect();
    if fields.len() < 2 {
        return bad("a pinned host key must be a complete OpenSSH public key line");
    }
    let key = ssh_key::PublicKey::from_openssh(pin)
        .map_err(|_| Error::InvalidTask("pinned host key is malformed".into()))?;
    Ok(key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

fn bad<T>(message: &str) -> Result<T, Error> {
    Err(Error::InvalidTask(message.into()))
}
