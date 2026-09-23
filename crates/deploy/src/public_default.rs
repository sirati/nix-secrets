use crate::{
    load_and_validate_manifest, DeployError, Deployer, DeploymentBatch, SecretClass,
    SecretDeployment,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::{Schema, SecretKind, SecretPath};
use std::fs;
use std::path::Path;

pub fn install_public_default(
    manifest: &Path,
    hostname: &str,
    identifier: &str,
    source: &Path,
    version: &str,
) -> Result<(), DeployError> {
    if version.is_empty()
        || version.len() > 256
        || !version.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DeployError::Invalid(
            "invalid public default version".into(),
        ));
    }
    let schema_text = fs::read_to_string(manifest)?;
    let schema =
        Schema::from_json(&schema_text).map_err(|e| DeployError::Invalid(e.to_string()))?;
    let path = SecretPath::parse(identifier).map_err(|e| DeployError::Invalid(e.to_string()))?;
    if path.components().first().map(String::as_str) != Some(hostname) {
        return Err(DeployError::Invalid(
            "public default belongs to another host".into(),
        ));
    }
    let spec = schema
        .secret(&path)
        .map_err(|e| DeployError::Invalid(e.to_string()))?;
    if !matches!(spec.kind, SecretKind::PublicInfo) || !spec.install_default_if_missing {
        return Err(DeployError::Invalid(
            "public default is not enabled by the manifest".into(),
        ));
    }
    let deployer = Deployer::public_info();
    if deployer.current_versions()?.contains_key(identifier)
        || fs::symlink_metadata(&spec.destination.path).is_ok()
    {
        return Ok(());
    }
    let metadata = fs::metadata(source)?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(DeployError::Invalid(
            "public default source is invalid".into(),
        ));
    }
    let value = fs::read(source)?;
    let batch = DeploymentBatch {
        version: 1,
        requested_identifiers: vec![identifier.into()],
        entries: vec![SecretDeployment {
            identifier: identifier.into(),
            version_id: version.into(),
            contents_base64: STANDARD.encode(value),
        }],
    };
    let resolved = load_and_validate_manifest(manifest, hostname, &batch)?;
    let (private, public) = resolved.partition();
    if !private.is_empty() || public.is_empty() || public.audit_details().len() != 1 {
        return Err(DeployError::Invalid(
            "public default did not resolve to one public destination".into(),
        ));
    }
    // The destination and contents were validated twice before entering the atomic publisher.
    let _ = SecretClass::PublicInfo;
    deployer.deploy(&public)
}
