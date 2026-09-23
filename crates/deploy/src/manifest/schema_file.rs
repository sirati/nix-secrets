use crate::DeployError;
use nix_secrets_core::schema::Schema;
use std::fs;
use std::path::Path;

const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

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
