use super::{Destination, GeneratedSecretLeaf, SchemaError, SecretKind, SecretNode, SecretPath};
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
            validate_description(&path, leaf.description.as_deref())?;
            match leaf.kind {
                SecretKind::Secret => {
                    if leaf.shared_public_id.is_some()
                        || leaf.expected_ssh_host.is_some()
                        || leaf.expected_ssh_port.is_some()
                        || leaf.install_default_if_missing
                    {
                        return Err(invalid(
                            &path,
                            "public-info fields require kind=public-info",
                        ));
                    }
                    validate_recipients(&path, &leaf.recipient_public_keys, &leaf.recipient_ids)?;
                    validate_destination(&path, service, &leaf.destination)?;
                    validate_value(&path, leaf.value_type, leaf.consumer_constraints.as_ref())?;
                    validate_value_generator(&path, leaf)?;
                    validate_derived_leaf(&path, leaf)
                }
                SecretKind::PublicInfo => {
                    if !leaf.recipient_public_keys.is_empty()
                        || !leaf.recipient_ids.is_empty()
                        || !leaf.recipient_names.is_empty()
                        || leaf.value_type.is_some()
                        || leaf.consumer_constraints.is_some()
                        || leaf.value_generator.is_some()
                        || leaf.derived_from.is_some()
                    {
                        return Err(invalid(
                            &path,
                            "public-info cannot have encryption or private value settings",
                        ));
                    }
                    validate_public_destination(&path, leaf)
                }
            }
        }
        SecretNode::Operator(leaf) => {
            let path = leaf_path(host, namespace, service, parents);
            validate_description(&path, leaf.description.as_deref())?;
            validate_recipients(&path, &leaf.recipient_public_keys, &leaf.recipient_ids)?;
            if leaf
                .recipient_public_keys
                .iter()
                .any(|key| !valid_ssh_public_key(key))
            {
                return Err(invalid(&path, "invalid OpenSSH recipient public key"));
            }
            if let Some(generator) = &leaf.generator {
                generator
                    .validate_definition()
                    .map_err(|message| SchemaError::InvalidValueDefinition(path, message))?;
            }
            Ok(())
        }
        SecretNode::Generated(leaf) => {
            validate_description(
                &leaf_path(host, namespace, service, parents),
                leaf.description.as_deref(),
            )?;
            validate_generated(leaf_path(host, namespace, service, parents), service, leaf)
        }
    }
}

fn validate_public_destination(
    path: &SecretPath,
    leaf: &super::SecretLeaf,
) -> Result<(), SchemaError> {
    let id = leaf
        .shared_public_id
        .as_deref()
        .ok_or_else(|| invalid(path, "public-info has no sharedPublicId"))?;
    if id.split('/').count() != 2
        || id.split('/').any(|part| {
            part.is_empty()
                || part.len() > 64
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
        || id.len() > 256
    {
        return Err(invalid(path, "invalid sharedPublicId"));
    }
    let destination = &leaf.destination;
    if destination.path != format!("/persistent/public-info/{id}")
        || destination.category != "public-info"
        || destination.owner != "root"
        || destination.group != "root"
        || destination.mode != "0644"
        || destination.content_type.as_deref() != Some("ssh-known-hosts")
        || destination.authorized_for_user.is_some()
    {
        return Err(invalid(
            path,
            "public-info destination must be its root-owned 0644 known-hosts path",
        ));
    }
    let host = leaf
        .expected_ssh_host
        .as_deref()
        .ok_or_else(|| invalid(path, "expectedSshHost is required"))?;
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        || leaf.expected_ssh_port.unwrap_or(0) == 0
    {
        return Err(invalid(path, "invalid expected SSH host or port"));
    }
    Ok(())
}

pub fn validate_ssh_known_hosts(value: &str, host: &str, port: u16) -> Result<(), &'static str> {
    if value.len() > 4096 || value.contains('\r') {
        return Err("known_hosts value is too large or contains carriage return");
    }
    let line = value.strip_suffix('\n').unwrap_or(value);
    if line.contains('\n') {
        return Err("known_hosts must contain exactly one key line");
    }
    let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != format!("[{host}]:{port}") || parts[1] != "ssh-ed25519" {
        return Err("known_hosts host, port, or key type does not match the schema");
    }
    if parts
        .iter()
        .any(|part| part.contains(['*', '?', ',', '@', '|', '#']))
    {
        return Err("known_hosts markers, wildcards, and host lists are forbidden");
    }
    if line != format!("{} {} {}", parts[0], parts[1], parts[2]) {
        return Err("known_hosts must use one canonical line");
    }
    let key = ssh_key::PublicKey::from_openssh(&format!("ssh-ed25519 {}", parts[2]))
        .map_err(|_| "invalid Ed25519 known_hosts key")?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err("known_hosts key is not Ed25519");
    }
    Ok(())
}

fn validate_description(path: &SecretPath, description: Option<&str>) -> Result<(), SchemaError> {
    if description.is_some_and(|value| {
        value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
    }) {
        return Err(invalid(
            path,
            "description must contain 1–512 printable bytes",
        ));
    }
    Ok(())
}

fn validate_generated(
    path: SecretPath,
    service: &str,
    leaf: &GeneratedSecretLeaf,
) -> Result<(), SchemaError> {
    validate_recipients(&path, &leaf.recipient_public_keys, &leaf.recipient_ids)?;
    validate_destination(&path, service, &leaf.generated_secret.output)?;
    validate_value(&path, leaf.value_type, leaf.consumer_constraints.as_ref())?;
    let bootstrap = match leaf.generated_secret.secret_type {
        super::GeneratedSecretType::StorageBoxSshKey => leaf
            .generated_secret
            .bootstrap
            .as_ref()
            .ok_or_else(|| invalid(&path, "storage-box bootstrap is missing"))?,
        super::GeneratedSecretType::LocalSshKey => {
            if leaf.generated_secret.bootstrap.is_some()
                || leaf.generated_secret.output.category != "service"
            {
                return Err(invalid(
                    &path,
                    "local SSH key must have a service output and no bootstrap",
                ));
            }
            if let Some(register_at) = &leaf.generated_secret.register_at {
                SecretPath::parse(register_at)
                    .map_err(|_| invalid(&path, "invalid registration secret identifier"))?;
            }
            return Ok(());
        }
    };
    if leaf.generated_secret.register_at.is_some() {
        return Err(invalid(
            &path,
            "storage-box key cannot register another secret",
        ));
    }
    if bootstrap.host.is_empty() || bootstrap.user.is_empty() {
        return Err(invalid(&path, "storage-box bootstrap is incomplete"));
    }
    if bootstrap.port != 23 {
        return Err(invalid(&path, "storage-box bootstrap port must be 23"));
    }
    if (bootstrap.host_public_keys.is_empty() == bootstrap.known_hosts_file.is_none())
        || bootstrap
            .host_public_keys
            .iter()
            .any(|key| !valid_ssh_public_key(key))
    {
        return Err(invalid(
            &path,
            "exactly one pinned host-key source is required",
        ));
    }
    if bootstrap
        .known_hosts_file
        .as_deref()
        .is_some_and(|file| !file.starts_with("/persistent/public-info/") || file.contains(".."))
    {
        return Err(invalid(&path, "invalid knownHostsFile path"));
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

fn validate_value(
    path: &SecretPath,
    value_type: Option<super::ValueType>,
    constraints: Option<&super::ConsumerConstraints>,
) -> Result<(), SchemaError> {
    if constraints.is_some() && value_type != Some(super::ValueType::Password) {
        return Err(SchemaError::InvalidValueDefinition(
            path.clone(),
            "consumerConstraints requires valueType=password".into(),
        ));
    }
    if let Some(constraints) = constraints {
        constraints
            .validate_definition()
            .map_err(|error| SchemaError::InvalidValueDefinition(path.clone(), error))?;
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
    if destination.content_type.as_deref().is_some_and(|kind| {
        !matches!(
            kind,
            "named-ssh-ed25519-public-keys" | "openssh-private-key" | "openssh-public-key"
        )
    }) {
        return Err(invalid(path, "unsupported secret content type"));
    }
    match (
        destination.content_type.as_deref(),
        destination.authorized_for_user.as_deref(),
    ) {
        (Some("named-ssh-ed25519-public-keys"), Some(user))
            if !user.is_empty()
                && user.len() <= 32
                && user
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) => {}
        (None, None) => {}
        (Some("openssh-private-key" | "openssh-public-key"), None) => {}
        _ => {
            return Err(invalid(
                path,
                "SSH key inventory requires a valid authorizedForUser",
            ));
        }
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

pub(crate) fn valid_ssh_public_key(key: &str) -> bool {
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

fn validate_value_generator(
    path: &SecretPath,
    leaf: &super::SecretLeaf,
) -> Result<(), SchemaError> {
    let Some(generator) = &leaf.value_generator else {
        return Ok(());
    };
    let fail = |message: String| SchemaError::InvalidValueDefinition(path.clone(), message);
    if leaf.external_input_required {
        return Err(fail(
            "valueGenerator contradicts externalInputRequired".into(),
        ));
    }
    if leaf.value_type == Some(super::ValueType::Password) {
        return Err(fail(
            "a password leaf uses the password generator; remove valueGenerator".into(),
        ));
    }
    if leaf.destination.content_type.is_some() {
        return Err(fail(
            "valueGenerator cannot produce a typed destination contentType".into(),
        ));
    }
    generator.validate_definition().map_err(fail)
}

fn validate_derived_leaf(path: &SecretPath, leaf: &super::SecretLeaf) -> Result<(), SchemaError> {
    let Some(derived) = &leaf.derived_from else {
        return Ok(());
    };
    let fail = |message: String| SchemaError::InvalidValueDefinition(path.clone(), message);
    if leaf.value_generator.is_some() || leaf.external_input_required {
        return Err(fail(
            "derivedFrom excludes valueGenerator and externalInputRequired".into(),
        ));
    }
    derived.validate_definition().map(|_| ()).map_err(fail)
}
