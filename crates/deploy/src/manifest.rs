use crate::schema::{ResolvedBatch, ResolvedSecret};
use crate::{DeployError, DeploymentBatch, SecretClass};
use base64::{engine::general_purpose::STANDARD, Engine};
use nix::unistd::{Group, User};
use nix_secrets_core::schema::{Destination, GeneratedSecretType, Schema, SecretNode};
use nix_secrets_transport::{
    Destination as WireDestination, PublicInfoAttestation, StorageBoxBootstrap as WireBootstrap,
    TargetSecret, TargetState, TargetTask, LOCAL_SSH_KEY, STORAGE_BOX_SSH_KEY,
};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

struct Expected {
    service: String,
    class: SecretClass,
    secret: String,
    owner: u32,
    group: u32,
    mode: u32,
}

struct ManifestEntry {
    service: String,
    destination: Destination,
    public_info: Option<PublicInfoAttestation>,
}

#[derive(Default)]
struct TargetLeaves {
    secrets: Vec<TargetSecret>,
    tasks: Vec<TargetTask>,
}

mod hostname;
pub use hostname::system_hostname;

pub fn load_and_validate_manifest(
    path: &Path,
    hostname: &str,
    batch: &DeploymentBatch,
) -> Result<ResolvedBatch, DeployError> {
    if !path.is_absolute() {
        return Err(DeployError::Invalid(
            "manifest path must be absolute".into(),
        ));
    }
    let schema = load_schema(path)?;
    validate_manifest(&schema, hostname, batch)
}

pub fn load_target_state(
    path: &Path,
    hostname: &str,
    versions: &BTreeMap<String, String>,
) -> Result<TargetState, DeployError> {
    let schema = load_schema(path)?;
    let host = schema
        .0
        .get(hostname)
        .ok_or_else(|| DeployError::Invalid(format!("manifest has no host {hostname}")))?;
    let mut leaves = TargetLeaves::default();
    for (namespace, services) in &host.service_groups {
        for (service, node) in services {
            flatten_target(
                hostname,
                namespace,
                service,
                &mut Vec::new(),
                node,
                versions,
                &mut leaves,
            );
        }
    }
    leaves
        .secrets
        .sort_unstable_by(|a, b| a.identifier.cmp(&b.identifier));
    leaves
        .tasks
        .sort_unstable_by(|a, b| a.identifier.cmp(&b.identifier));
    Ok(TargetState {
        protocol_version: nix_secrets_transport::DEPLOYMENT_PROTOCOL_VERSION,
        hostname: hostname.into(),
        secrets: leaves.secrets,
        tasks: leaves.tasks,
    })
}

mod schema_file;
pub(crate) use schema_file::load_schema;

fn flatten_target(
    hostname: &str,
    namespace: &str,
    service: &str,
    parents: &mut Vec<String>,
    node: &SecretNode,
    versions: &BTreeMap<String, String>,
    output: &mut TargetLeaves,
) {
    match node {
        // Operator-only values never reach a host.
        SecretNode::Operator(_) => {}
        SecretNode::Branch(children) => {
            for (name, child) in children {
                parents.push(name.clone());
                flatten_target(
                    hostname, namespace, service, parents, child, versions, output,
                );
                parents.pop();
            }
        }
        SecretNode::Secret(leaf) => {
            let identifier = identifier(hostname, namespace, service, parents);
            output.secrets.push(TargetSecret {
                identifier: identifier.clone(),
                recipient_ids: leaf.recipient_ids.clone(),
                destination: WireDestination {
                    path: leaf.destination.path.clone(),
                    category: leaf.destination.category.clone(),
                    owner: leaf.destination.owner.clone(),
                    group: leaf.destination.group.clone(),
                    mode: leaf.destination.mode.clone(),
                    consumer_units: leaf.consumer_units.clone(),
                },
                public_info: leaf.shared_public_id.as_ref().map(|shared_id| {
                    PublicInfoAttestation {
                        shared_id: shared_id.clone(),
                        expected_ssh_host: leaf.expected_ssh_host.clone().unwrap_or_default(),
                        expected_ssh_port: leaf.expected_ssh_port.unwrap_or_default(),
                    }
                }),
                current_version_id: versions.get(&identifier).cloned(),
                generator: leaf
                    .deployment_generator()
                    .ok()
                    .map(|generator| generator.fingerprint()),
            });
        }
        SecretNode::Generated(leaf) => {
            let identifier = identifier(hostname, namespace, service, parents);
            let generated = &leaf.generated_secret;
            output.tasks.push(TargetTask {
                identifier: identifier.clone(),
                task_type: match generated.secret_type {
                    GeneratedSecretType::StorageBoxSshKey => STORAGE_BOX_SSH_KEY,
                    GeneratedSecretType::LocalSshKey => LOCAL_SSH_KEY,
                }
                .into(),
                recipient_ids: leaf.recipient_ids.clone(),
                output: wire_destination(&generated.output, &leaf.consumer_units),
                bootstrap: generated.bootstrap.as_ref().map(|bootstrap| WireBootstrap {
                    host: bootstrap.host.clone(),
                    port: bootstrap.port,
                    user: bootstrap.user.clone(),
                    host_public_keys: bootstrap.host_public_keys.clone(),
                    known_hosts_file: bootstrap.known_hosts_file.clone(),
                }),
                current_version_id: versions.get(&identifier).cloned(),
            });
        }
    }
}

fn identifier(host: &str, namespace: &str, service: &str, parents: &[String]) -> String {
    std::iter::once(host)
        .chain(std::iter::once(namespace))
        .chain(std::iter::once(service))
        .chain(parents.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(".")
}

fn wire_destination(value: &Destination, consumers: &[String]) -> WireDestination {
    WireDestination {
        path: value.path.clone(),
        category: value.category.clone(),
        owner: value.owner.clone(),
        group: value.group.clone(),
        mode: value.mode.clone(),
        consumer_units: consumers.to_vec(),
    }
}

fn validate_manifest(
    schema: &Schema,
    hostname: &str,
    batch: &DeploymentBatch,
) -> Result<ResolvedBatch, DeployError> {
    if !matches!(batch.version, 1 | 2) {
        return Err(DeployError::Invalid(
            "unsupported deployment version".into(),
        ));
    }
    let host = schema
        .0
        .get(hostname)
        .ok_or_else(|| DeployError::Invalid(format!("manifest has no host {hostname}")))?;
    let mut expected = HashMap::new();
    for (namespace, services) in &host.service_groups {
        for (service, node) in services {
            flatten(
                hostname,
                namespace,
                service,
                &mut Vec::new(),
                node,
                &mut expected,
            )?;
        }
    }
    if batch.requested_identifiers.is_empty() {
        return Err(DeployError::Invalid(
            "deployment requests no secrets".into(),
        ));
    }
    let requested: std::collections::BTreeSet<&str> = batch
        .requested_identifiers
        .iter()
        .map(String::as_str)
        .collect();
    if requested.len() != batch.requested_identifiers.len() {
        return Err(DeployError::Invalid(
            "deployment contains duplicate requested identifiers".into(),
        ));
    }
    let mut supplied = HashMap::new();
    for entry in &batch.entries {
        if supplied.insert(entry.identifier.as_str(), entry).is_some() {
            return Err(DeployError::Invalid(format!(
                "duplicate secret identifier: {}",
                entry.identifier
            )));
        }
    }
    if supplied.len() != requested.len()
        || supplied
            .keys()
            .any(|identifier| !requested.contains(identifier))
    {
        return Err(DeployError::Invalid(
            "deployment entries do not exactly match the requested identifiers".into(),
        ));
    }
    let mut entries = Vec::with_capacity(requested.len());
    for requested_identifier in requested {
        let identifier = requested_identifier.to_owned();
        let manifest_entry = expected.remove(&identifier).ok_or_else(|| {
            DeployError::Invalid(format!(
                "requested secret is absent from manifest: {identifier}"
            ))
        })?;
        let spec = expected_from_destination(&manifest_entry.service, &manifest_entry.destination)?;
        let supplied = supplied
            .get(identifier.as_str())
            .ok_or_else(|| DeployError::Invalid(format!("missing secret: {identifier}")))?;
        if supplied.version_id.is_empty() || supplied.version_id.len() > 256 {
            return Err(DeployError::Invalid(format!(
                "invalid version for {identifier}"
            )));
        }
        let contents = STANDARD
            .decode(&supplied.contents_base64)
            .map_err(|_| DeployError::Invalid(format!("invalid base64 for {identifier}")))?;
        if let Some(public) = &manifest_entry.public_info {
            let text = std::str::from_utf8(&contents)
                .map_err(|_| DeployError::Invalid("public-info value is not UTF-8".into()))?;
            nix_secrets_core::schema::validate_ssh_known_hosts(
                text,
                &public.expected_ssh_host,
                public.expected_ssh_port,
            )
            .map_err(|error| DeployError::Invalid(error.into()))?;
            if manifest_entry.destination.path
                != format!("/persistent/public-info/{}", public.shared_id)
            {
                return Err(DeployError::Invalid(
                    "public-info destination does not match its shared ID".into(),
                ));
            }
        }
        if manifest_entry.destination.content_type.as_deref()
            == Some("named-ssh-ed25519-public-keys")
        {
            validate_named_ssh_keys(&contents)?;
        }
        match manifest_entry.destination.content_type.as_deref() {
            Some("openssh-private-key") => {
                let text = std::str::from_utf8(&contents)
                    .map_err(|_| DeployError::Invalid("SSH private key is not UTF-8".into()))?;
                let key = ssh_key::PrivateKey::from_openssh(text)
                    .map_err(|_| DeployError::Invalid("invalid OpenSSH private key".into()))?;
                if key.is_encrypted() {
                    return Err(DeployError::Invalid(
                        "OpenSSH private key requires an interactive passphrase".into(),
                    ));
                }
            }
            Some("openssh-public-key") => {
                let text = std::str::from_utf8(&contents)
                    .map_err(|_| DeployError::Invalid("SSH public key is not UTF-8".into()))?;
                ssh_key::PublicKey::from_openssh(text.trim())
                    .map_err(|_| DeployError::Invalid("invalid OpenSSH public key".into()))?;
            }
            _ => {}
        }
        let audit_key_names = if manifest_entry.destination.content_type.as_deref()
            == Some("named-ssh-ed25519-public-keys")
        {
            std::str::from_utf8(&contents)
                .expect("validated public key inventory is UTF-8")
                .lines()
                .filter_map(|line| line.split_ascii_whitespace().next())
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        };
        entries.push(ResolvedSecret {
            identifier,
            version_id: supplied.version_id.clone(),
            service: spec.service,
            class: spec.class,
            secret: spec.secret,
            contents,
            owner: spec.owner,
            group: spec.group,
            mode: spec.mode,
            audit_ssh_user: manifest_entry.destination.authorized_for_user.clone(),
            audit_key_names,
        });
    }
    Ok(ResolvedBatch { entries })
}

mod named_keys;
use named_keys::validate_named_ssh_keys;
mod flatten;
use flatten::{expected_from_destination, flatten};
