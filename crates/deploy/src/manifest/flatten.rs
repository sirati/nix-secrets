use super::*;

pub(super) fn flatten(
    hostname: &str,
    namespace: &str,
    service: &str,
    parents: &mut Vec<String>,
    node: &SecretNode,
    output: &mut HashMap<String, ManifestEntry>,
) -> Result<(), DeployError> {
    match node {
        SecretNode::Branch(children) => {
            flatten_children(hostname, namespace, service, parents, children, output)
        }
        SecretNode::Secret(leaf) => {
            let mut parts = vec![
                hostname.to_owned(),
                namespace.to_owned(),
                service.to_owned(),
            ];
            parts.extend(parents.iter().cloned());
            let identifier = parts.join(".");
            let spec = ManifestEntry {
                service: service.into(),
                destination: leaf.destination.clone(),
            };
            if output.insert(identifier.clone(), spec).is_some() {
                return Err(DeployError::Invalid(format!(
                    "duplicate manifest identifier: {identifier}"
                )));
            }
            Ok(())
        }
        SecretNode::Generated(leaf) => {
            let mut parts = vec![
                hostname.to_owned(),
                namespace.to_owned(),
                service.to_owned(),
            ];
            parts.extend(parents.iter().cloned());
            let identifier = parts.join(".");
            let spec = ManifestEntry {
                service: service.into(),
                destination: leaf.generated_secret.output.clone(),
            };
            if output.insert(identifier.clone(), spec).is_some() {
                return Err(DeployError::Invalid(format!(
                    "duplicate manifest identifier: {identifier}"
                )));
            }
            Ok(())
        }
    }
}

fn flatten_children(
    hostname: &str,
    namespace: &str,
    service: &str,
    parents: &mut Vec<String>,
    children: &BTreeMap<String, SecretNode>,
    output: &mut HashMap<String, ManifestEntry>,
) -> Result<(), DeployError> {
    for (name, child) in children {
        parents.push(name.clone());
        flatten(hostname, namespace, service, parents, child, output)?;
        parents.pop();
    }
    Ok(())
}

pub(super) fn expected_from_destination(
    service: &str,
    destination: &Destination,
) -> Result<Expected, DeployError> {
    let class = match destination.category.as_str() {
        "setup" => SecretClass::Setup,
        "service" => SecretClass::Service,
        "backup" => SecretClass::Backup,
        _ => {
            return Err(DeployError::Invalid(
                "manifest has invalid secret category".into(),
            ))
        }
    };
    let expected_parent = PathBuf::from("/persistent/secrets")
        .join(service)
        .join(class.directory());
    let path = Path::new(&destination.path);
    if path.parent() != Some(expected_parent.as_path()) {
        return Err(DeployError::Invalid(format!(
            "manifest destination is outside service boundary: {}",
            path.display()
        )));
    }
    let secret = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| DeployError::Invalid("manifest destination has no UTF-8 filename".into()))?;
    crate::validate::validate_name("secret", secret)?;
    let owner = User::from_name(&destination.owner)
        .map_err(errno)?
        .ok_or_else(|| DeployError::Invalid(format!("unknown owner: {}", destination.owner)))?
        .uid
        .as_raw();
    let group = Group::from_name(&destination.group)
        .map_err(errno)?
        .ok_or_else(|| DeployError::Invalid(format!("unknown group: {}", destination.group)))?
        .gid
        .as_raw();
    let mode_text = destination
        .mode
        .strip_prefix("0o")
        .unwrap_or(&destination.mode);
    let mode = u32::from_str_radix(mode_text, 8)
        .map_err(|_| DeployError::Invalid(format!("invalid mode: {}", destination.mode)))?;
    crate::validate::validate_mode(mode)?;
    Ok(Expected {
        service: service.into(),
        class,
        secret: secret.into(),
        owner,
        group,
        mode,
    })
}
