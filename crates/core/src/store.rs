use crate::schema::{
    LeafSpec, Schema, SchemaError, SecretKind, SecretPath, validate_ssh_known_hosts,
};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

mod committed;
mod generated_metadata;
pub use committed::CommitState;
mod persistence;
mod public_info;
mod validation;
use validation::{hydrate_record, validate_public_metadata, validate_record};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSecret {
    pub format_version: u16,
    /// Opaque random identifier generated whenever the value is replaced.
    #[serde(with = "base64_bytes")]
    pub version_id: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipient_ids: Vec<String>,
    /// Registry references keep repeated recipient fingerprints out of TOML records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipient_refs: Vec<String>,
    /// A complete age file encoded for TOML storage.
    #[serde(with = "base64_bytes")]
    pub age_ciphertext: Vec<u8>,
    /// Plaintext public half of an OpenSSH private key, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedPublicKey {
    pub version_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicInfoRecord {
    pub version_id: String,
    pub value: String,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreDocument {
    #[serde(default)]
    secrets: BTreeMap<String, EncryptedSecret>,
    #[serde(default)]
    generated_public_keys: BTreeMap<String, GeneratedPublicKey>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    recipient_registry: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    public_info: BTreeMap<String, PublicInfoRecord>,
}

pub struct SecretStore {
    path: PathBuf,
    lock_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid TOML: {0}")]
    Decode(#[from] toml::de::Error),
    #[error("cannot encode TOML: {0}")]
    Encode(#[from] toml::ser::Error),
    #[error(transparent)]
    Schema(#[from] SchemaError),
    #[error("envelope recipient does not match the evaluated schema")]
    RecipientMismatch,
    #[error("stored age record metadata is invalid")]
    InvalidRecord,
    #[error("public key metadata does not match the evaluated secret type")]
    InvalidPublicKey,
    #[error("recipient registry reference is missing or inconsistent")]
    InvalidRecipientRegistry,
    #[error("public-info value or schema is invalid")]
    InvalidPublicInfo,
    #[error("secret version changed during update")]
    VersionConflict,
}

impl SecretStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let lock_path = path.with_extension("toml.lock");
        Self { path, lock_path }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn get(&self, path: &SecretPath) -> Result<Option<EncryptedSecret>, StoreError> {
        self.with_lock(false, |document| {
            document
                .secrets
                .get(&path.to_string())
                .map(|record| hydrate_record(document, record))
                .transpose()
        })
    }

    pub fn list(&self) -> Result<BTreeMap<String, EncryptedSecret>, StoreError> {
        self.with_lock(false, |document| {
            document
                .secrets
                .iter()
                .map(|(path, record)| Ok((path.clone(), hydrate_record(document, record)?)))
                .collect()
        })
    }

    pub fn set(
        &self,
        schema: &Schema,
        path: &SecretPath,
        envelope: EncryptedSecret,
    ) -> Result<(), StoreError> {
        self.set_checked(schema, path, envelope, None)
    }

    pub fn set_if_version(
        &self,
        schema: &Schema,
        path: &SecretPath,
        envelope: EncryptedSecret,
        expected_version: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        self.set_checked(schema, path, envelope, Some(expected_version))
    }

    fn set_checked(
        &self,
        schema: &Schema,
        path: &SecretPath,
        mut envelope: EncryptedSecret,
        expected_version: Option<Option<&[u8]>>,
    ) -> Result<(), StoreError> {
        let leaf = schema.leaf(path)?;
        if matches!(&leaf, LeafSpec::Stored(spec) if matches!(spec.kind, SecretKind::PublicInfo)) {
            return Err(StoreError::InvalidPublicInfo);
        }
        let recipients = match &leaf {
            LeafSpec::Stored(spec) => &spec.recipient_ids,
            LeafSpec::Generated(spec) => &spec.recipient_ids,
        };
        if *recipients != envelope.recipient_ids {
            return Err(StoreError::RecipientMismatch);
        }
        validate_public_metadata(&leaf, envelope.public_key.as_deref())?;
        validate_record(&envelope)?;
        let names = match &leaf {
            LeafSpec::Stored(spec) => &spec.recipient_names,
            LeafSpec::Generated(spec) => &spec.recipient_names,
        };
        self.with_lock(true, |document| {
            if let Some(expected) = expected_version {
                let actual = document
                    .secrets
                    .get(&path.to_string())
                    .map(|value| value.version_id.as_slice());
                if actual != expected {
                    return Err(StoreError::VersionConflict);
                }
            }
            if !names.is_empty() {
                if names.len() != envelope.recipient_ids.len() {
                    return Err(StoreError::InvalidRecipientRegistry);
                }
                let mut refs = Vec::with_capacity(names.len());
                for (name, id) in names.iter().zip(&envelope.recipient_ids) {
                    let reference = document
                        .recipient_registry
                        .iter()
                        .find(|(reference, value)| {
                            reference.starts_with(&format!("{name}#")) && *value == id
                        })
                        .map(|(reference, _)| reference.clone())
                        .unwrap_or_else(|| {
                            let mut revision = 0_u32;
                            loop {
                                let reference = format!("{name}#{revision}");
                                if !document.recipient_registry.contains_key(&reference) {
                                    break reference;
                                }
                                revision += 1;
                            }
                        });
                    document
                        .recipient_registry
                        .entry(reference.clone())
                        .or_insert_with(|| id.clone());
                    refs.push(reference);
                }
                envelope.recipient_refs = refs;
                envelope.recipient_ids.clear();
            } else {
                envelope.recipient_refs.clear();
            }
            document.secrets.insert(path.to_string(), envelope);
            Ok(())
        })
    }

    pub fn remove(&self, schema: &Schema, path: &SecretPath) -> Result<bool, StoreError> {
        if matches!(schema.leaf(path)?, LeafSpec::Stored(spec) if matches!(spec.kind, SecretKind::PublicInfo))
        {
            return Err(StoreError::InvalidPublicInfo);
        }
        self.with_lock(true, |document| {
            Ok(document.secrets.remove(&path.to_string()).is_some())
        })
    }

    pub fn remove_if_version(
        &self,
        schema: &Schema,
        path: &SecretPath,
        expected_version: &[u8],
    ) -> Result<bool, StoreError> {
        if matches!(schema.leaf(path)?, LeafSpec::Stored(spec) if matches!(spec.kind, SecretKind::PublicInfo))
        {
            return Err(StoreError::InvalidPublicInfo);
        }
        self.with_lock(true, |document| {
            let actual = document
                .secrets
                .get(&path.to_string())
                .map(|value| value.version_id.as_slice());
            if actual != Some(expected_version) {
                return Err(StoreError::VersionConflict);
            }
            Ok(document.secrets.remove(&path.to_string()).is_some())
        })
    }
}

mod base64_bytes {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        STANDARD.decode(value).map_err(serde::de::Error::custom)
    }
}
