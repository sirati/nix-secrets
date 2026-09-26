use super::*;

pub(super) fn validate_shared_public_specs(
    host: &str,
    node: &SecretNode,
    seen: &mut BTreeMap<String, (String, u16)>,
) -> Result<(), SchemaError> {
    match node {
        SecretNode::Branch(children) => {
            for child in children.values() {
                validate_shared_public_specs(host, child, seen)?;
            }
            Ok(())
        }
        SecretNode::Secret(leaf) if matches!(leaf.kind, SecretKind::PublicInfo) => {
            let id = leaf
                .shared_public_id
                .as_ref()
                .expect("validated public-info ID");
            let value = (
                leaf.expected_ssh_host.clone().expect("validated SSH host"),
                leaf.expected_ssh_port.expect("validated SSH port"),
            );
            if seen.get(id).is_some_and(|previous| previous != &value) {
                return Err(SchemaError::InvalidDestination(
                    synthetic_path(host),
                    "shared public-info ID has conflicting validation settings".into(),
                ));
            }
            seen.insert(id.clone(), value);
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(super) fn validate_named_recipients(
    host: &str,
    node: &SecretNode,
    registry: &BTreeMap<String, String>,
) -> Result<(), SchemaError> {
    match node {
        SecretNode::Branch(children) => {
            for child in children.values() {
                validate_named_recipients(host, child, registry)?;
            }
            Ok(())
        }
        SecretNode::Secret(leaf) => check_recipient_names(
            host,
            &leaf.recipient_names,
            &leaf.recipient_public_keys,
            registry,
        ),
        SecretNode::Generated(leaf) => check_recipient_names(
            host,
            &leaf.recipient_names,
            &leaf.recipient_public_keys,
            registry,
        ),
        SecretNode::Operator(leaf) => check_recipient_names(
            host,
            &leaf.recipient_names,
            &leaf.recipient_public_keys,
            registry,
        ),
    }
}

fn check_recipient_names(
    host: &str,
    names: &[String],
    keys: &[String],
    registry: &BTreeMap<String, String>,
) -> Result<(), SchemaError> {
    if names.is_empty() {
        return Ok(());
    }
    let path = synthetic_path(host);
    if names.len() != keys.len()
        || names.iter().zip(keys).any(|(name, key)| {
            name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
                || registry.get(name) != Some(key)
        })
    {
        return Err(SchemaError::InvalidDestination(
            path,
            "named recipient does not match the host registry".into(),
        ));
    }
    let mut unique = names.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() != names.len() {
        return Err(SchemaError::InvalidDestination(
            path,
            "duplicate recipient name".into(),
        ));
    }
    Ok(())
}

pub(super) fn missing(path: &SecretPath) -> SchemaError {
    SchemaError::NotFound(path.clone())
}

pub(super) fn synthetic_path(host: &str) -> SecretPath {
    SecretPath(vec![
        host.into(),
        "services".into(),
        "metadata".into(),
        "socket".into(),
    ])
}
