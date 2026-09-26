//! Values the target generates for itself during deployment.
//!
//! The operator asks for a value it does not have. The target produces it from
//! its own kernel randomness, with the operator's contribution mixed in,
//! installs it, and returns only an age ciphertext to the leaf's recipients.
//!
//! Retries converge: if the target already has a nix-secrets version of the
//! value installed, it re-encrypts that value under the installed version
//! instead of generating a new one. A failed store write on the operator side
//! therefore never leaves the host with a value the next deployment replaces.

use crate::manifest::load_schema;
use crate::{DeployError, SecretDeployment};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nix_secrets_core::generator::OsRandom;
use nix_secrets_core::schema::deployment_generator;
use nix_secrets_core::{LeafSpec, SecretPath};
use nix_secrets_crypto::{
    encrypt_secret_with_version, CryptoProvider, Recipient, MAX_SECRET_SIZE, VERSION_ID_SIZE,
};
use nix_secrets_transport::{GenerateEntry, GeneratedRecord};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroizing;

pub struct GeneratedValues {
    pub deployments: Vec<SecretDeployment>,
    pub records: BTreeMap<String, GeneratedRecord>,
}

/// Where generated values come from and where installed ones are read.
pub trait GenerationHost {
    /// Mixes the operator's contribution into the entropy source.
    fn mix(&mut self, contribution: &[u8]) -> Result<(), DeployError>;
    fn generate(
        &mut self,
        generator: &nix_secrets_core::DeployGenerator,
    ) -> Result<Zeroizing<Vec<u8>>, DeployError>;
    fn fresh_version(&mut self) -> Result<[u8; VERSION_ID_SIZE], DeployError>;
    /// Reads the installed value at a manifest destination.
    fn read_installed(&mut self, path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, DeployError>;
}

/// The production host: `/dev/urandom` and the live secret tree.
pub struct SystemHost;

impl GenerationHost for SystemHost {
    fn mix(&mut self, contribution: &[u8]) -> Result<(), DeployError> {
        // Writing to /dev/urandom mixes the bytes into the kernel pool
        // without crediting entropy, exactly as target key tasks do.
        let mut pool = OpenOptions::new().write(true).open("/dev/urandom")?;
        pool.write_all(contribution)?;
        pool.flush()?;
        Ok(())
    }

    fn generate(
        &mut self,
        generator: &nix_secrets_core::DeployGenerator,
    ) -> Result<Zeroizing<Vec<u8>>, DeployError> {
        generator
            .generate_with(&mut OsRandom)
            .map_err(DeployError::Invalid)
    }

    fn fresh_version(&mut self) -> Result<[u8; VERSION_ID_SIZE], DeployError> {
        let mut version = [0_u8; VERSION_ID_SIZE];
        getrandom::fill(&mut version)
            .map_err(|_| DeployError::Invalid("operating-system randomness failed".into()))?;
        Ok(version)
    }

    fn read_installed(&mut self, path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, DeployError> {
        read_installed(path)
    }
}

/// Generates the requested values and then frames the requested derived
/// values from them. A derived value's source must be among `entries`: the
/// target frames only what it just generated or adopted, so it never needs a
/// value the operator did not ask it to produce.
pub fn run_value_generation(
    manifest: &Path,
    hostname: &str,
    entries: &[GenerateEntry],
    derive: &[String],
    installed_versions: &BTreeMap<String, String>,
    provider: &impl CryptoProvider,
    host: &mut impl GenerationHost,
) -> Result<GeneratedValues, DeployError> {
    let schema = load_schema(manifest)?;
    let mut produced: BTreeMap<String, ([u8; VERSION_ID_SIZE], Zeroizing<Vec<u8>>)> =
        BTreeMap::new();
    let mut deployments = Vec::with_capacity(entries.len() + derive.len());
    let mut records = BTreeMap::new();
    for entry in entries {
        let path = SecretPath::parse(&entry.identifier)
            .map_err(|error| invalid(format!("invalid generated identifier: {error}")))?;
        if path.components().first().map(String::as_str) != Some(hostname) {
            return Err(invalid("generated value belongs to another host"));
        }
        let LeafSpec::Stored(spec) = schema.leaf(&path).map_err(|error| {
            invalid(format!("generated value is absent from manifest: {error}"))
        })?
        else {
            return Err(invalid("target tasks cannot be generated as values"));
        };
        let generator = deployment_generator(&spec).map_err(|reason| {
            invalid(format!(
                "{} cannot be generated here: {}",
                entry.identifier,
                reason.reason()
            ))
        })?;
        let contribution = Zeroizing::new(
            STANDARD
                .decode(&entry.client_contribution_base64)
                .map_err(|_| invalid("client contribution is not valid base64"))?,
        );
        if contribution.len() != 32 {
            return Err(invalid("client contribution must be exactly 32 bytes"));
        }
        let installed = match installed_versions.get(&entry.identifier) {
            Some(version) => host
                .read_installed(Path::new(&spec.destination.path))?
                .map(|value| (version.clone(), value)),
            None => None,
        };
        let adopted = installed.is_some();
        let (version, value) = match installed {
            Some((installed_version, value)) => {
                let version = match decode_version(&installed_version) {
                    Some(version) => version,
                    // Keep the value but give it a store-compatible version.
                    None => host.fresh_version()?,
                };
                (version, value)
            }
            None => {
                host.mix(&contribution)?;
                (host.fresh_version()?, host.generate(&generator)?)
            }
        };
        let recipients = spec
            .recipient_ids
            .iter()
            .zip(&spec.recipient_public_keys)
            .map(|(id, key)| Recipient {
                id,
                ssh_public_key: key,
            })
            .collect::<Vec<_>>();
        let encrypted =
            encrypt_secret_with_version(&entry.identifier, version, &value, &recipients, provider)
                .map_err(|error| {
                    invalid(format!("cannot encrypt {}: {error}", entry.identifier))
                })?;
        let version_id = STANDARD.encode(version);
        produced.insert(entry.identifier.clone(), (version, value.clone()));
        deployments.push(SecretDeployment {
            identifier: entry.identifier.clone(),
            version_id: version_id.clone(),
            contents_base64: STANDARD.encode(value.as_slice()),
        });
        records.insert(
            entry.identifier.clone(),
            GeneratedRecord {
                format_version: encrypted.format_version,
                version_id_base64: version_id,
                recipient_ids: encrypted.recipient_ids,
                age_ciphertext_base64: STANDARD.encode(&encrypted.age_ciphertext),
                adopted,
            },
        );
    }
    for identifier in derive {
        let path = SecretPath::parse(identifier)
            .map_err(|error| invalid(format!("invalid derived identifier: {error}")))?;
        if path.components().first().map(String::as_str) != Some(hostname) {
            return Err(invalid("derived value belongs to another host"));
        }
        let LeafSpec::Stored(spec) = schema
            .leaf(&path)
            .map_err(|error| invalid(format!("derived value is absent from manifest: {error}")))?
        else {
            return Err(invalid("only stored values can be derived"));
        };
        let derived = spec
            .derived_from
            .ok_or_else(|| invalid(format!("{identifier} declares no derivedFrom")))?;
        let (version, value) = produced.get(&derived.identifier).ok_or_else(|| {
            invalid(format!(
                "{identifier}: its source {} is not generated in this deployment",
                derived.identifier
            ))
        })?;
        deployments.push(SecretDeployment {
            identifier: identifier.clone(),
            version_id: derived.version(version),
            contents_base64: STANDARD.encode(derived.frame(value).as_slice()),
        });
    }
    Ok(GeneratedValues {
        deployments,
        records,
    })
}

fn decode_version(value: &str) -> Option<[u8; VERSION_ID_SIZE]> {
    STANDARD.decode(value).ok()?.try_into().ok()
}

fn read_installed(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, DeployError> {
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
    if !metadata.is_file() || metadata.len() > MAX_SECRET_SIZE as u64 {
        return Err(invalid("installed value is not a bounded regular file"));
    }
    let mut value = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.read_to_end(&mut value)?;
    Ok(Some(value))
}

fn invalid(message: impl Into<String>) -> DeployError {
    DeployError::Invalid(message.into())
}

#[cfg(test)]
mod tests;
