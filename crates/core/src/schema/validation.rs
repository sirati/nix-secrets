use super::{Destination, GeneratedSecretLeaf, SchemaError, SecretNode, SecretPath};
use base64::Engine;

pub(super) fn validate_tree(
    host: &str,
    namespace: &str,
    service: &str,
    parents: &[String],
    node: &SecretNode,
) -> Result<(), SchemaError> {
    match node {
        SecretNode::Branch(children) => {
            for (name, child) in children {
                validate_component(name)?;
                let mut path = parents.to_vec();
                path.push(name.clone());
                validate_tree(host, namespace, service, &path, child)?;
            }
            Ok(())
        }
        SecretNode::Secret(leaf) => {
            let path = leaf_path(host, namespace, service, parents);
            validate_recipients(&path, &leaf.recipient_public_keys, &leaf.recipient_ids)?;
            validate_destination(&path, service, &leaf.destination)
        }
        SecretNode::Generated(leaf) => {
            validate_generated(leaf_path(host, namespace, service, parents), service, leaf)
        }
    }
}

fn validate_generated(
    path: SecretPath,
    service: &str,
    leaf: &GeneratedSecretLeaf,
) -> Result<(), SchemaError> {
    validate_recipients(&path, &leaf.recipient_public_keys, &leaf.recipient_ids)?;
    validate_destination(&path, service, &leaf.generated_secret.output)?;
    let bootstrap = &leaf.generated_secret.bootstrap;
    if bootstrap.host.is_empty() || bootstrap.user.is_empty() {
        return Err(invalid(&path, "storage-box bootstrap is incomplete"));
    }
    if bootstrap.port != 23 {
        return Err(invalid(&path, "storage-box bootstrap port must be 23"));
    }
    if bootstrap.host_public_keys.is_empty()
        || bootstrap
            .host_public_keys
            .iter()
            .any(|key| !valid_ssh_public_key(key))
    {
        return Err(invalid(&path, "invalid pinned OpenSSH host public key"));
    }
    let mut unique_keys = bootstrap.host_public_keys.clone();
    unique_keys.sort();
    unique_keys.dedup();
    if unique_keys.len() != bootstrap.host_public_keys.len() {
        return Err(invalid(&path, "duplicate pinned OpenSSH host public key"));
    }
    if leaf
        .recipient_public_keys
        .iter()
        .any(|key| !valid_ssh_public_key(key))
    {
        return Err(invalid(&path, "invalid OpenSSH recipient public key"));
    }
    Ok(())
}

fn validate_recipients(
    path: &SecretPath,
    public_keys: &[String],
    ids: &[String],
) -> Result<(), SchemaError> {
    if public_keys.is_empty() {
        return Err(SchemaError::MissingPublicKey(path.clone()));
    }
    if public_keys.len() != ids.len() {
        return Err(SchemaError::RecipientCount(path.clone()));
    }
    Ok(())
}

fn validate_destination(
    path: &SecretPath,
    service: &str,
    destination: &Destination,
) -> Result<(), SchemaError> {
    if !matches!(
        destination.category.as_str(),
        "setup" | "service" | "backup"
    ) {
        return Err(invalid(path, "invalid category"));
    }
    if destination.owner.is_empty() || destination.group.is_empty() {
        return Err(invalid(path, "owner and group must not be empty"));
    }
    if !matches!(destination.mode.as_str(), "0400" | "0440") {
        return Err(invalid(path, "mode must be 0400 or 0440"));
    }
    let prefix = format!("/persistent/secrets/{service}/{}/", destination.category);
    let name = destination.path.strip_prefix(&prefix).unwrap_or_default();
    if name.is_empty() || name.contains('/') {
        return Err(invalid(
            path,
            &format!("path must be directly below {prefix}"),
        ));
    }
    Ok(())
}

fn valid_ssh_public_key(key: &str) -> bool {
    if key.trim() != key || key.contains(['\r', '\n']) {
        return false;
    }
    let mut fields = key.split_ascii_whitespace();
    let Some(algorithm) = fields.next() else {
        return false;
    };
    let Some(encoded) = fields.next() else {
        return false;
    };
    if !matches!(
        algorithm,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
    ) {
        return false;
    }
    let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Some((embedded, remainder)) = ssh_string(&blob) else {
        return false;
    };
    embedded == algorithm.as_bytes() && valid_key_blob(algorithm, remainder)
}

fn valid_key_blob(algorithm: &str, input: &[u8]) -> bool {
    match algorithm {
        "ssh-ed25519" => {
            ssh_string(input).is_some_and(|(key, rest)| key.len() == 32 && rest.is_empty())
        }
        "ssh-rsa" => ssh_string(input).is_some_and(|(exponent, rest)| {
            !exponent.is_empty()
                && ssh_string(rest)
                    .is_some_and(|(modulus, tail)| !modulus.is_empty() && tail.is_empty())
        }),
        algorithm if algorithm.starts_with("ecdsa-sha2-") => {
            ssh_string(input).is_some_and(|(curve, rest)| {
                algorithm.as_bytes().strip_prefix(b"ecdsa-sha2-") == Some(curve)
                    && ssh_string(rest)
                        .is_some_and(|(point, tail)| !point.is_empty() && tail.is_empty())
            })
        }
        _ => false,
    }
}

fn ssh_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    Some((input.get(4..4 + length)?, input.get(4 + length..)?))
}

fn leaf_path(host: &str, namespace: &str, service: &str, parents: &[String]) -> SecretPath {
    let mut components = vec![host.into(), namespace.into(), service.into()];
    components.extend_from_slice(parents);
    SecretPath(components)
}

fn invalid(path: &SecretPath, message: &str) -> SchemaError {
    SchemaError::InvalidDestination(path.clone(), message.into())
}

pub(super) fn validate_component(component: &str) -> Result<(), SchemaError> {
    let valid = !component.is_empty()
        && component
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'));
    valid
        .then_some(())
        .ok_or_else(|| SchemaError::InvalidComponent(component.into()))
}

pub(super) fn validate_namespace(namespace: &str) -> Result<(), SchemaError> {
    let valid = namespace == "services"
        || (namespace.starts_with("user-") && namespace.ends_with("-services"));
    valid
        .then_some(())
        .ok_or_else(|| SchemaError::InvalidNamespace(namespace.into()))
}
