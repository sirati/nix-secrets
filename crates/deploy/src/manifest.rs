use crate::schema::{ResolvedBatch, ResolvedSecret};
use crate::{DeployError, DeploymentBatch, SecretClass};
use base64::{engine::general_purpose::STANDARD, Engine};
use nix::unistd::{Group, User};
use nix_secrets_core::schema::{Destination, Schema, SecretNode};
use nix_secrets_transport::{
    Destination as WireDestination, StorageBoxBootstrap as WireBootstrap, TargetSecret,
    TargetState, TargetTask, STORAGE_BOX_SSH_KEY,
};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

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
}

pub fn system_hostname() -> Result<String, DeployError> {
    let value = fs::read_to_string("/proc/sys/kernel/hostname")?;
    let hostname = value.trim().to_owned();
    if hostname.is_empty() {
        Err(DeployError::Invalid("system hostname is empty".into()))
    } else {
        Ok(hostname)
    }
}

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
    let mut secrets = Vec::new();
    let mut tasks = Vec::new();
    for (namespace, services) in &host.service_groups {
        for (service, node) in services {
            flatten_target(
                hostname,
                namespace,
                service,
                &mut Vec::new(),
                node,
                versions,
                &mut secrets,
                &mut tasks,
            );
        }
    }
    secrets.sort_unstable_by(|a, b| a.identifier.cmp(&b.identifier));
    tasks.sort_unstable_by(|a, b| a.identifier.cmp(&b.identifier));
    Ok(TargetState {
        protocol_version: 1,
        hostname: hostname.into(),
        secrets,
        tasks,
    })
}

pub(crate) fn load_schema(path: &Path) -> Result<Schema, DeployError> {
    if !path.is_absolute() {
        return Err(DeployError::Invalid(
            "manifest path must be absolute".into(),
        ));
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(DeployError::Invalid(
            "manifest must be a regular file no larger than 16 MiB".into(),
        ));
    }
    let input = fs::read_to_string(path)?;
    Schema::from_json(&input)
        .map_err(|error| DeployError::Invalid(format!("invalid manifest: {error}")))
}

fn flatten_target(
    hostname: &str,
    namespace: &str,
    service: &str,
    parents: &mut Vec<String>,
    node: &SecretNode,
    versions: &BTreeMap<String, String>,
    output: &mut Vec<TargetSecret>,
    tasks: &mut Vec<TargetTask>,
) {
    match node {
        SecretNode::Branch(children) => {
            for (name, child) in children {
                parents.push(name.clone());
                flatten_target(
                    hostname, namespace, service, parents, child, versions, output, tasks,
                );
                parents.pop();
            }
        }
        SecretNode::Secret(leaf) => {
            let identifier = identifier(hostname, namespace, service, parents);
            output.push(TargetSecret {
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
                current_version_id: versions.get(&identifier).cloned(),
            });
        }
        SecretNode::Generated(leaf) => {
            let identifier = identifier(hostname, namespace, service, parents);
            let generated = &leaf.generated_secret;
            tasks.push(TargetTask {
                identifier: identifier.clone(),
                task_type: STORAGE_BOX_SSH_KEY.into(),
                recipient_ids: leaf.recipient_ids.clone(),
                output: wire_destination(&generated.output, &leaf.consumer_units),
                bootstrap: WireBootstrap {
                    host: generated.bootstrap.host.clone(),
                    port: generated.bootstrap.port,
                    user: generated.bootstrap.user.clone(),
                    host_public_keys: generated.bootstrap.host_public_keys.clone(),
                },
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
    if batch.version != 1 {
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
        });
    }
    Ok(ResolvedBatch { entries })
}

mod flatten;
use flatten::{expected_from_destination, flatten};

fn errno(error: nix::errno::Errno) -> DeployError {
    DeployError::Invalid(format!("account lookup failed: {error}"))
}
