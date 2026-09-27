use crate::manifest::load_schema;
use crate::{DeployError, SecretDeployment};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nix::unistd::{Group, User};
use nix_secrets_core::schema::SecretNode;
use nix_secrets_core::{GeneratedSecretType, Schema, SecretKind, SecretPath};
use nix_secrets_storagebox_bootstrap::{
    ClientContribution, DevUrandom, Engine, OsKeyGenerator, Output, RusshBackend, StorageBoxTask,
    SystemClock,
};
use nix_secrets_transport::TaskEntry;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

const MAX_PASSWORD_BYTES: usize = 64 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;

pub struct GeneratedTasks {
    pub deployments: Vec<SecretDeployment>,
    pub public_keys: BTreeMap<String, String>,
    /// Tasks left out because a prerequisite is absent on this host, with
    /// why. Everything else in the batch deploys.
    pub not_deployed: BTreeMap<String, String>,
}

pub fn run_generated_tasks(
    manifest: &Path,
    hostname: &str,
    entries: &[TaskEntry],
) -> Result<GeneratedTasks, DeployError> {
    run_generated_tasks_with(manifest, hostname, entries, &[])
}

/// Runs the tasks of a batch that also supplies `supplied` values. Public
/// information among them is published in the same generation as the
/// tasks' output, so a task reads its known_hosts from the batch.
pub fn run_generated_tasks_with(
    manifest: &Path,
    hostname: &str,
    entries: &[TaskEntry],
    supplied: &[SecretDeployment],
) -> Result<GeneratedTasks, DeployError> {
    let schema = load_schema(manifest)?;
    let mut pending = BTreeMap::new();
    for item in supplied {
        let Ok(path) = SecretPath::parse(&item.identifier) else {
            continue;
        };
        if let Ok(nix_secrets_core::LeafSpec::Stored(spec)) = schema.leaf(&path) {
            if matches!(spec.kind, SecretKind::PublicInfo) {
                let value = STANDARD
                    .decode(&item.contents_base64)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .ok_or_else(|| invalid(format!("{} is not UTF-8 base64", item.identifier)))?;
                pending.insert(spec.destination.path.clone(), value);
            }
        }
    }
    let mut outputs = Vec::with_capacity(entries.len());
    let mut public_keys = BTreeMap::new();
    let mut not_deployed = BTreeMap::new();
    for entry in entries {
        let path = SecretPath::parse(&entry.identifier)
            .map_err(|error| invalid(format!("invalid task identifier: {error}")))?;
        if path.components().first().map(String::as_str) != Some(hostname) {
            return Err(invalid("generated task belongs to another host"));
        }
        let spec = schema
            .generated_secret(&path)
            .map_err(|error| invalid(format!("generated task is absent from manifest: {error}")))?;
        let generated = spec.generated_secret;
        validate_output(&path, &generated.output)?;
        let mode = parse_mode(&generated.output.mode)?;
        let contribution = decode_contribution(&entry.client_contribution_base64)?;
        if matches!(generated.secret_type, GeneratedSecretType::LocalSshKey) {
            if !entry.password_base64.is_empty() {
                return Err(invalid(
                    "local SSH key task must not have a bootstrap password",
                ));
            }
            use nix_secrets_storagebox_bootstrap::KeyGenerator;
            let mut entropy = DevUrandom::open().map_err(task_error)?;
            std::io::Write::write_all(&mut entropy, contribution.expose()).map_err(task_error)?;
            std::io::Write::flush(&mut entropy).map_err(task_error)?;
            let existing = read_existing_key(Path::new(&generated.output.path))
                .map_err(|error| error.during(&format!("reading the installed key {} for task {}", generated.output.path, entry.identifier)))?;
            let key = match existing {
                Some(value) => {
                    nix_secrets_storagebox_bootstrap::GeneratedKey::from_private_pem(&value)
                        .map_err(task_error)?
                }
                None => OsKeyGenerator.generate().map_err(task_error)?,
            };
            let stamp = time::OffsetDateTime::now_utc()
                .format(
                    &time::format_description::parse_borrowed::<2>(
                        "[year][month][day]T[hour][minute][second][subsecond digits:3]Z",
                    )
                    .map_err(task_error)?,
                )
                .map_err(task_error)?;
            public_keys.insert(
                entry.identifier.clone(),
                format!("{stamp} {}", key.public_key),
            );
            outputs.push(SecretDeployment {
                identifier: entry.identifier.clone(),
                version_id: entry.version_id.clone(),
                contents_base64: STANDARD.encode(key.private_pem.as_bytes()),
            });
            continue;
        }
        let bootstrap = generated
            .bootstrap
            .ok_or_else(|| invalid("storage box bootstrap missing"))?;
        let pinned_host_keys = if let Some(file) = bootstrap.known_hosts_file.as_deref() {
            match read_attested_known_hosts(
                &schema,
                &pending,
                hostname,
                &entry.identifier,
                file,
                &bootstrap.host,
                bootstrap.port,
            ) {
                Ok(keys) => keys,
                Err(DeployError::Missing(reason)) => {
                    not_deployed.insert(entry.identifier.clone(), reason);
                    continue;
                }
                Err(error) => return Err(error),
            }
        } else {
            bootstrap.host_public_keys
        };
        let password = decode_password(&entry.password_base64)?;
        let task = StorageBoxTask {
            schema_version: 1,
            task_id: entry.identifier.clone(),
            target_hostname: hostname.into(),
            storage_box_host: bootstrap.host,
            storage_box_user: bootstrap.user,
            port: bootstrap.port,
            pinned_host_keys,
            output: Output {
                path: generated.output.path.clone(),
                owner: generated.output.owner,
                group: generated.output.group,
                mode,
            },
        };
        let existing = read_existing_key(Path::new(&task.output.path))
            .map_err(|error| error.during(&format!("reading the installed key {} for task {}", task.output.path, entry.identifier)))?;
        let mut engine = Engine {
            backend: RusshBackend,
            entropy: DevUrandom::open().map_err(task_error)?,
            generator: OsKeyGenerator,
            clock: SystemClock,
        };
        let key = engine
            .run(
                &task,
                password,
                contribution,
                existing.as_ref().map(|value| value.as_str()),
            )
            .map_err(|error| {
                invalid(format!(
                    "task {}: Storage Box bootstrap on {}:{} failed: {error}",
                    entry.identifier, task.storage_box_host, task.port
                ))
            })?;
        public_keys.insert(entry.identifier.clone(), key.public_key.clone());
        outputs.push(SecretDeployment {
            identifier: entry.identifier.clone(),
            version_id: entry.version_id.clone(),
            contents_base64: STANDARD.encode(key.private_pem.as_bytes()),
        });
    }
    Ok(GeneratedTasks {
        deployments: outputs,
        public_keys,
        not_deployed,
    })
}

fn read_attested_known_hosts(
    schema: &Schema,
    pending: &BTreeMap<String, String>,
    hostname: &str,
    task: &str,
    file: &str,
    host: &str,
    port: u16,
) -> Result<Vec<String>, DeployError> {
    let host_schema = schema
        .0
        .get(hostname)
        .ok_or_else(|| invalid("host is absent from manifest"))?;
    // The public-info leaf whose destination is the file and whose
    // known_hosts may name this host and port.
    fn attesting<'a>(
        node: &'a SecretNode,
        file: &str,
        host: &str,
        port: u16,
    ) -> Option<&'a nix_secrets_core::schema::SecretLeaf> {
        match node {
            SecretNode::Secret(leaf) => (matches!(leaf.kind, SecretKind::PublicInfo)
                && leaf.destination.path == file
                && leaf.ssh_hosts().contains(&host)
                && leaf.expected_ssh_port == Some(port))
            .then_some(leaf),
            SecretNode::Branch(children) => children
                .values()
                .find_map(|child| attesting(child, file, host, port)),
            SecretNode::Generated(_) | SecretNode::Operator(_) => None,
        }
    }
    let leaf = host_schema
        .service_groups
        .values()
        .flat_map(|services| services.values())
        .find_map(|node| attesting(node, file, host, port))
        .ok_or_else(|| {
            invalid(format!(
                "task {task}: knownHostsFile {file} is not a public-info destination attesting [{host}]:{port}"
            ))
        })?;
    let what = format!("reading the Storage Box known_hosts {file} for task {task}");
    let hosts = leaf.ssh_hosts();
    let keys_of = |value: &str| {
        nix_secrets_core::schema::known_hosts_keys(value, &hosts, port, host)
            .map_err(|error| invalid(format!("{what}: {error}")))
            .and_then(|keys| {
                if keys.is_empty() {
                    Err(DeployError::Missing(format!(
                        "{file} holds no key for [{host}]:{port}"
                    )))
                } else {
                    Ok(keys)
                }
            })
    };
    if let Some(value) = pending.get(file) {
        return keys_of(value);
    }
    let mut handle = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(file)
    {
        Ok(handle) => handle,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(DeployError::Missing(format!(
                "{file} is absent: its public information is not installed on this host yet"
            )))
        }
        Err(error) => return Err(DeployError::context(&what, error)),
    };
    let meta = handle
        .metadata()
        .map_err(|error| DeployError::context(&what, error))?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.permissions().mode() & 0o777 != 0o644
        || meta.len() > nix_secrets_core::schema::MAX_KNOWN_HOSTS_BYTES as u64
    {
        return Err(invalid(format!(
            "{what}: it has invalid ownership, mode, or length"
        )));
    }
    let mut value = String::new();
    handle
        .read_to_string(&mut value)
        .map_err(|error| DeployError::context(&what, error))?;
    keys_of(&value)
}

fn decode_password(value: &str) -> Result<Zeroizing<Vec<u8>>, DeployError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| invalid("task password is not valid base64"))?,
    );
    if decoded.is_empty() || decoded.len() > MAX_PASSWORD_BYTES {
        return Err(invalid("task password has invalid length"));
    }
    Ok(decoded)
}

fn decode_contribution(value: &str) -> Result<ClientContribution, DeployError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| invalid("client contribution is not valid base64"))?,
    );
    let bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| invalid("client contribution must be exactly 32 bytes"))?;
    Ok(ClientContribution::new(bytes))
}

fn read_existing_key(path: &Path) -> Result<Option<Zeroizing<String>>, DeployError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(invalid(
            "existing generated key is not a bounded regular file",
        ));
    }
    let mut value = Zeroizing::new(String::with_capacity(metadata.len() as usize));
    file.read_to_string(&mut value)?;
    Ok(Some(value))
}

fn parse_mode(value: &str) -> Result<u32, DeployError> {
    let value = value.strip_prefix("0o").unwrap_or(value);
    let mode = u32::from_str_radix(value, 8).map_err(|_| invalid("invalid output mode"))?;
    if matches!(mode, 0o400 | 0o440) {
        Ok(mode)
    } else {
        Err(invalid("generated output mode must be 0400 or 0440"))
    }
}

fn validate_output(
    identifier: &SecretPath,
    output: &nix_secrets_core::Destination,
) -> Result<(), DeployError> {
    let service = identifier
        .components()
        .get(2)
        .ok_or_else(|| invalid("task identifier has no service"))?;
    let expected = Path::new("/persistent/secrets")
        .join(service)
        .join(&output.category);
    let path = Path::new(&output.path);
    if path.parent() != Some(expected.as_path())
        || !matches!(output.category.as_str(), "backup" | "service")
    {
        return Err(invalid(
            "generated task output escapes its backup service boundary",
        ));
    }
    User::from_name(&output.owner)
        .map_err(|_| invalid("cannot resolve generated output owner"))?
        .ok_or_else(|| invalid("generated output owner does not exist"))?;
    Group::from_name(&output.group)
        .map_err(|_| invalid("cannot resolve generated output group"))?
        .ok_or_else(|| invalid("generated output group does not exist"))?;
    parse_mode(&output.mode)?;
    Ok(())
}

fn task_error(error: impl std::fmt::Display) -> DeployError {
    invalid(format!("storage box bootstrap failed: {error}"))
}

fn invalid(message: impl Into<String>) -> DeployError {
    DeployError::Invalid(message.into())
}
