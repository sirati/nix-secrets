use crate::schema::{LeafSpec, Schema, SchemaError, SecretPath};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSecret {
    pub format_version: u16,
    /// Opaque random identifier generated whenever the value is replaced.
    #[serde(with = "base64_bytes")]
    pub version_id: Vec<u8>,
    pub recipient_ids: Vec<String>,
    /// A complete age file encoded for TOML storage.
    #[serde(with = "base64_bytes")]
    pub age_ciphertext: Vec<u8>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreDocument {
    #[serde(default)]
    secrets: BTreeMap<String, EncryptedSecret>,
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
    #[error("secret version changed during update")]
    VersionConflict,
}

impl SecretStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let lock_path = path.with_extension("toml.lock");
        Self { path, lock_path }
    }

    pub fn get(&self, path: &SecretPath) -> Result<Option<EncryptedSecret>, StoreError> {
        self.with_lock(false, |document| {
            Ok(document.secrets.get(&path.to_string()).cloned())
        })
    }

    pub fn list(&self) -> Result<BTreeMap<String, EncryptedSecret>, StoreError> {
        self.with_lock(false, |document| Ok(document.secrets.clone()))
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
        envelope: EncryptedSecret,
        expected_version: Option<Option<&[u8]>>,
    ) -> Result<(), StoreError> {
        let recipients = match schema.leaf(path)? {
            LeafSpec::Stored(spec) => spec.recipient_ids,
            LeafSpec::Generated(spec) => spec.recipient_ids,
        };
        if recipients != envelope.recipient_ids {
            return Err(StoreError::RecipientMismatch);
        }
        validate_record(&envelope)?;
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
            document.secrets.insert(path.to_string(), envelope);
            Ok(())
        })
    }

    pub fn remove(&self, schema: &Schema, path: &SecretPath) -> Result<bool, StoreError> {
        schema.leaf(path)?;
        self.with_lock(true, |document| {
            Ok(document.secrets.remove(&path.to_string()).is_some())
        })
    }

    fn with_lock<T>(
        &self,
        write: bool,
        action: impl FnOnce(&mut StoreDocument) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&self.lock_path)?;
        flock(
            &lock,
            if write {
                FlockOperation::LockExclusive
            } else {
                FlockOperation::LockShared
            },
        )
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
        let mut document = self.read_document()?;
        let result = action(&mut document)?;
        if write {
            self.write_document(parent, &document)?;
        }
        Ok(result)
    }

    fn read_document(&self) -> Result<StoreDocument, StoreError> {
        match fs::read_to_string(&self.path) {
            Ok(value) => Ok(toml::from_str(&value)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(StoreDocument::default()),
            Err(error) => Err(error.into()),
        }
    }

    fn write_document(&self, parent: &Path, document: &StoreDocument) -> Result<(), StoreError> {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let name = format!(".nix-secrets.{}.{}.tmp", std::process::id(), id);
        let temp_path = parent.join(name);
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        let result = (|| {
            temp.write_all(toml::to_string_pretty(document)?.as_bytes())?;
            temp.sync_all()?;
            fs::rename(&temp_path, &self.path)?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
            File::open(parent)?.sync_all()?;
            Ok::<_, StoreError>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp_path);
        }
        result
    }
}

fn validate_record(record: &EncryptedSecret) -> Result<(), StoreError> {
    const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024 * 1024;
    if record.format_version != 1
        || record.version_id.len() != 16
        || record.recipient_ids.is_empty()
        || record.age_ciphertext.is_empty()
        || record.age_ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(StoreError::InvalidRecord);
    }
    Ok(())
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
