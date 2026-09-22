use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeSet;

pub(super) fn validate_task_spec(
    identifier: &str,
    kind: &str,
    output: &Destination,
    bootstrap: &StorageBoxBootstrap,
) -> Result<(), DeploymentError> {
    if kind != STORAGE_BOX_SSH_KEY {
        return Err(DeploymentError::Invalid("unsupported generated task type"));
    }
    if bootstrap.port != 23 || bootstrap.host.is_empty() || bootstrap.user.is_empty() {
        return Err(DeploymentError::Invalid("invalid storage box endpoint"));
    }
    let mut unique = BTreeSet::new();
    if bootstrap.host_public_keys.is_empty()
        || bootstrap
            .host_public_keys
            .iter()
            .any(|key| !valid_host_key(key) || !unique.insert(key))
    {
        return Err(DeploymentError::Invalid(
            "invalid pinned storage box host key",
        ));
    }
    validate_output(identifier, output)
}

fn validate_output(identifier: &str, output: &Destination) -> Result<(), DeploymentError> {
    let service = identifier
        .split('.')
        .nth(2)
        .ok_or(DeploymentError::Invalid("invalid task identifier"))?;
    let parts = output.path.split('/').collect::<Vec<_>>();
    let valid_path = parts.len() == 6
        && parts[..3] == ["", "persistent", "secrets"]
        && parts[3] == service
        && parts[4] == output.category
        && !parts[5].is_empty();
    if !valid_path
        || !matches!(output.category.as_str(), "setup" | "service" | "backup")
        || !matches!(output.mode.as_str(), "0400" | "0440")
        || output.owner.is_empty()
        || output.group.is_empty()
    {
        Err(DeploymentError::Invalid("invalid generated task output"))
    } else {
        Ok(())
    }
}

fn valid_host_key(key: &str) -> bool {
    if key.contains(['\n', '\r']) {
        return false;
    }
    let mut parts = key.split_whitespace();
    let algorithm = parts.next();
    let encoded = parts.next();
    if !matches!(
        algorithm,
        Some(
            "ssh-ed25519"
                | "ssh-rsa"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
        )
    ) {
        return false;
    }
    encoded
        .and_then(|value| STANDARD.decode(value).ok())
        .is_some_and(|blob| !blob.is_empty())
}
