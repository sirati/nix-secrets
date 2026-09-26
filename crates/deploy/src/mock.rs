//! Test-only installation of mock values for every leaf of a host manifest.
//!
//! A NixOS test configuration enables `services.nixSecrets.mock`, whose unit
//! runs `secret-deploy --mock-install`. It computes a value for each leaf
//! that is not installed yet and publishes them through the same validation
//! ([`load_and_validate_manifest`]) and the same atomic publisher
//! ([`Deployer`]) as a real deployment. Ownership, modes, generations, service
//! links, versions and readiness therefore behave exactly as in production.
//!
//! The mock never reads or writes `nix-secrets.toml`, never talks to a
//! backend and never contacts a Storage Box. Explicit values come from the
//! Nix configuration and are therefore world-readable in the Nix store: they
//! must be non-secret test data.
//!
//! Value sources, per leaf, in order:
//! - an explicit value;
//! - with `generate_rest`:
//!   - a stored leaf with a deploy generator: that generator, the same code
//!     deploy-time generation uses;
//!   - a derived leaf: its source's mock value (explicit, generated in this
//!     run, or already installed), framed with the real `DerivedFrom`
//!     framing and version. An explicit value for a derived leaf is taken
//!     as its source value and framed. A source on another host gets a random
//!     value, since that host's mock value is unknown here;
//!   - a generated-secret task: a fresh Ed25519 private key;
//!   - public information: a known-hosts line for its expected host and port;
//!   - anything else: a value that passes the receiver's content checks
//!     (a key, a public key, a named key inventory, or random text).
//!
//! Only leaves without an installed version are written, so mock values stay
//! stable across reboots and a completely installed host is left untouched.

use crate::manifest::load_schema;
use crate::{load_and_validate_manifest, DeployError, Deployer, DeploymentBatch, SecretClass};
use crate::{ResolvedBatch, SecretDeployment};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use nix_secrets_core::generator::OsRandom;
use nix_secrets_core::schema::{
    Destination, GeneratedSecretLeaf, HostSchema, SecretKind, SecretLeaf, SecretNode,
};
use nix_secrets_core::SecretPath;
use nix_secrets_crypto::VERSION_ID_SIZE;
use nix_secrets_storagebox_bootstrap::{KeyGenerator, OsKeyGenerator};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroizing;

const MAX_VALUES_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INSTALLED_BYTES: u64 = 1024 * 1024;

/// What a mock installation did.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct MockReport {
    /// Identifiers published by this run, sorted.
    pub installed: Vec<String>,
    /// Leaves that were already installed and left untouched.
    pub already_installed: usize,
}

/// Reads the `{identifier: value}` JSON object the NixOS module writes.
pub fn load_mock_values(path: &Path) -> Result<BTreeMap<String, String>, DeployError> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_VALUES_BYTES {
        return Err(invalid(
            "mock values must be a regular file of at most 16 MiB",
        ));
    }
    serde_json::from_slice(&std::fs::read(path)?)
        .map_err(|error| invalid(format!("invalid mock values: {error}")))
}

/// Installs a mock value for every leaf of `hostname` in `manifest` that
/// `secrets` and `public` do not have yet.
pub fn mock_install(
    manifest: &Path,
    hostname: &str,
    values: &BTreeMap<String, String>,
    generate_rest: bool,
    secrets: &Deployer,
    public: &Deployer,
) -> Result<MockReport, DeployError> {
    let schema = load_schema(manifest)?;
    let host = schema
        .0
        .get(hostname)
        .ok_or_else(|| invalid(format!("manifest has no host {hostname}")))?;
    let leaves = host_leaves(hostname, host);
    let unknown: Vec<&str> = values
        .keys()
        .filter(|identifier| !leaves.contains_key(identifier.as_str()))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return Err(invalid(format!(
            "mock values name no deployable leaf of {hostname}: {}",
            unknown.join(", ")
        )));
    }
    let secret_versions = secrets.current_versions()?;
    let mut installed = secret_versions.clone();
    installed.extend(public.current_versions()?);
    let pending: Vec<(&str, &Leaf<'_>)> = leaves
        .iter()
        .filter(|(identifier, _)| !installed.contains_key(identifier.as_str()))
        .map(|(identifier, leaf)| (identifier.as_str(), leaf))
        .collect();
    let mut report = MockReport {
        installed: Vec::new(),
        already_installed: leaves.len() - pending.len(),
    };
    if pending.is_empty() {
        return Ok(report);
    }

    let mut produced: BTreeMap<String, (Vec<u8>, Zeroizing<Vec<u8>>)> = BTreeMap::new();
    let mut missing = Vec::new();
    // Sources first, so a derived leaf can frame its source's mock value.
    for (identifier, leaf) in pending.iter().filter(|(_, leaf)| !leaf.is_derived()) {
        let explicit = values.get(*identifier);
        let value = match (explicit, leaf) {
            (Some(value), _) => Some(Zeroizing::new(value.as_bytes().to_vec())),
            (None, _) if !generate_rest => None,
            (None, Leaf::Stored(stored)) => Some(generate_stored(identifier, stored)?),
            (None, Leaf::Task(_)) => Some(private_key()?),
        };
        match value {
            Some(value) => {
                produced.insert((*identifier).to_owned(), (fresh_version()?.to_vec(), value));
            }
            None => missing.push((*identifier).to_owned()),
        }
    }
    for (identifier, leaf) in pending.iter().filter(|(_, leaf)| leaf.is_derived()) {
        let Leaf::Stored(stored) = leaf else {
            unreachable!("only stored leaves are derived")
        };
        let derived = stored
            .derived_from
            .as_ref()
            .expect("filtered for derived leaves");
        // An explicit value is the source value, framed like a real one.
        let source = if let Some(value) = values.get(*identifier) {
            Some((
                fresh_version()?.to_vec(),
                Zeroizing::new(value.as_bytes().to_vec()),
            ))
        } else if let Some((version, value)) = produced.get(&derived.identifier) {
            Some((version.clone(), value.clone()))
        } else if let Some(version) = secret_versions.get(&derived.identifier) {
            let source = leaves.get(derived.identifier.as_str()).ok_or_else(|| {
                invalid(format!(
                    "{identifier}: installed source {} is not in the manifest",
                    derived.identifier
                ))
            })?;
            let value = read_installed(secrets, &derived.identifier, source.destination())?;
            let version = STANDARD
                .decode(version)
                .unwrap_or_else(|_| version.as_bytes().to_vec());
            Some((version, value))
        } else if leaves.contains_key(derived.identifier.as_str()) {
            // A same-host source that has no value source itself.
            None
        } else if generate_rest {
            // The source lives on another host whose mock value is unknown
            // here; the framing is still the real one.
            Some((fresh_version()?.to_vec(), random_text()?))
        } else {
            None
        };
        match source {
            Some((version, value)) => {
                produced.insert(
                    (*identifier).to_owned(),
                    (
                        derived.version(&version).into_bytes(),
                        derived.frame(&value),
                    ),
                );
            }
            None => missing.push((*identifier).to_owned()),
        }
    }
    if !missing.is_empty() {
        missing.sort();
        return Err(invalid(format!(
            "mock values missing (set services.nixSecrets.mock.values or generateRest): {}",
            missing.join(", ")
        )));
    }

    let mut entries = Vec::with_capacity(produced.len());
    for (identifier, (version, value)) in &produced {
        let version_id = if leaves[identifier.as_str()].is_derived() {
            String::from_utf8(version.clone()).expect("derived versions are text")
        } else {
            STANDARD.encode(version)
        };
        entries.push(SecretDeployment {
            identifier: identifier.clone(),
            version_id,
            contents_base64: STANDARD.encode(value.as_slice()),
        });
    }
    let batch = DeploymentBatch {
        version: 2,
        requested_identifiers: produced.keys().cloned().collect(),
        entries,
    };
    let resolved = load_and_validate_manifest(manifest, hostname, &batch)?;
    publish(resolved, secrets, public)?;
    report.installed = batch.requested_identifiers.clone();
    Ok(report)
}

/// The receiver's publish step: public information and secrets each go to
/// their own atomic tree.
fn publish(
    resolved: ResolvedBatch,
    secrets: &Deployer,
    public: &Deployer,
) -> Result<(), DeployError> {
    let (private, public_batch) = resolved.partition();
    if !public_batch.is_empty() {
        public.deploy(&public_batch)?;
    }
    if !private.is_empty() {
        secrets.deploy(&private)?;
    }
    Ok(())
}

enum Leaf<'a> {
    Stored(&'a SecretLeaf),
    Task(&'a GeneratedSecretLeaf),
}

impl Leaf<'_> {
    fn is_derived(&self) -> bool {
        matches!(self, Leaf::Stored(leaf) if leaf.derived_from.is_some())
    }

    fn destination(&self) -> &Destination {
        match self {
            Leaf::Stored(leaf) => &leaf.destination,
            Leaf::Task(leaf) => &leaf.generated_secret.output,
        }
    }
}

/// Every leaf that a deployment can install on this host.
fn host_leaves<'a>(hostname: &str, host: &'a HostSchema) -> BTreeMap<String, Leaf<'a>> {
    fn walk<'a>(prefix: String, node: &'a SecretNode, output: &mut BTreeMap<String, Leaf<'a>>) {
        match node {
            // Operator-only values never reach a host.
            SecretNode::Operator(_) => {}
            SecretNode::Secret(leaf) => {
                output.insert(prefix, Leaf::Stored(leaf));
            }
            SecretNode::Generated(leaf) => {
                output.insert(prefix, Leaf::Task(leaf));
            }
            SecretNode::Branch(children) => {
                for (name, child) in children {
                    walk(format!("{prefix}.{name}"), child, output);
                }
            }
        }
    }
    let mut output = BTreeMap::new();
    for (namespace, services) in &host.service_groups {
        for (service, node) in services {
            walk(
                format!("{hostname}.{namespace}.{service}"),
                node,
                &mut output,
            );
        }
    }
    output
}

fn generate_stored(identifier: &str, leaf: &SecretLeaf) -> Result<Zeroizing<Vec<u8>>, DeployError> {
    if let Ok(generator) = leaf.deployment_generator() {
        return generator
            .generate_with(&mut OsRandom)
            .map_err(|error| invalid(format!("{identifier}: {error}")));
    }
    if matches!(leaf.kind, SecretKind::PublicInfo) {
        let host = leaf.expected_ssh_host.as_deref().unwrap_or_default();
        let port = leaf.expected_ssh_port.unwrap_or_default();
        return Ok(Zeroizing::new(
            format!("[{host}]:{port} {}\n", public_key()?).into_bytes(),
        ));
    }
    match leaf.destination.content_type.as_deref() {
        Some("openssh-private-key") => private_key(),
        Some("openssh-public-key") => {
            Ok(Zeroizing::new(format!("{}\n", public_key()?).into_bytes()))
        }
        Some("named-ssh-ed25519-public-keys") => Ok(Zeroizing::new(
            format!("mock-{} {}\n", stamp()?, public_key()?).into_bytes(),
        )),
        _ => random_text(),
    }
}

fn private_key() -> Result<Zeroizing<Vec<u8>>, DeployError> {
    let key = OsKeyGenerator.generate().map_err(key_error)?;
    Ok(Zeroizing::new(key.private_pem.as_bytes().to_vec()))
}

/// `ssh-ed25519 <base64>` of a fresh key, without a comment.
fn public_key() -> Result<String, DeployError> {
    let key = OsKeyGenerator.generate().map_err(key_error)?;
    let mut parts = key.public_key.split_ascii_whitespace();
    match (parts.next(), parts.next()) {
        (Some(algorithm), Some(encoded)) => Ok(format!("{algorithm} {encoded}")),
        _ => Err(invalid("generated public key has an unexpected format")),
    }
}

fn random_text() -> Result<Zeroizing<Vec<u8>>, DeployError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| invalid("operating-system randomness failed"))?;
    Ok(Zeroizing::new(
        URL_SAFE_NO_PAD.encode(bytes.as_ref()).into_bytes(),
    ))
}

fn fresh_version() -> Result<[u8; VERSION_ID_SIZE], DeployError> {
    let mut version = [0_u8; VERSION_ID_SIZE];
    getrandom::fill(&mut version).map_err(|_| invalid("operating-system randomness failed"))?;
    Ok(version)
}

fn stamp() -> Result<String, DeployError> {
    let format =
        time::format_description::parse_borrowed::<2>("[year][month][day]T[hour][minute][second]Z")
            .map_err(|error| invalid(error.to_string()))?;
    time::OffsetDateTime::now_utc()
        .format(&format)
        .map_err(|error| invalid(error.to_string()))
}

/// Reads an installed stored value through the deployer's stable path.
fn read_installed(
    secrets: &Deployer,
    identifier: &str,
    destination: &Destination,
) -> Result<Zeroizing<Vec<u8>>, DeployError> {
    let path = SecretPath::parse(identifier).map_err(|error| invalid(error.to_string()))?;
    let service = &path.components()[2];
    let class = match destination.category.as_str() {
        "setup" => SecretClass::Setup,
        "service" => SecretClass::Service,
        "backup" => SecretClass::Backup,
        _ => return Err(invalid(format!("{identifier} is not a stored secret"))),
    };
    let secret = Path::new(&destination.path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid(format!("{identifier} has no destination file name")))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC)
        .open(secrets.secret_path(service, class, secret)?)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_INSTALLED_BYTES {
        return Err(invalid(format!(
            "installed {identifier} is not a bounded regular file"
        )));
    }
    let mut value = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.read_to_end(&mut value)?;
    Ok(value)
}

fn key_error(error: impl std::fmt::Display) -> DeployError {
    invalid(format!("mock key generation failed: {error}"))
}

fn invalid(message: impl Into<String>) -> DeployError {
    DeployError::Invalid(message.into())
}

#[cfg(test)]
mod tests;
