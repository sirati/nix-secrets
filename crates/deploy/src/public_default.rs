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
    // Finish an interrupted joint deployment before reading the versions.
    deployer.recover_alone()?;
    if deployer.current_versions()?.contains_key(identifier)
        || fs::symlink_metadata(&spec.destination.path).is_ok()
    {
        return Ok(());
    }
    let metadata = fs::metadata(source)?;
    if !metadata.is_file() || metadata.len() > nix_secrets_core::schema::MAX_KNOWN_HOSTS_BYTES as u64 {
        return Err(DeployError::Invalid(
            "public default source is invalid".into(),
        ));
    }
    let value = fs::read(source)?;
    let Some((value, version)) = usable_default(&spec, identifier, value, version) else {
        return Ok(());
    };
    let batch = DeploymentBatch {
        version: 1,
        requested_identifiers: vec![identifier.into()],
        entries: vec![SecretDeployment {
            identifier: identifier.into(),
            version_id: version,
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

/// The value to install and its version. The source is the operator store's
/// record when it has one, which may predate this host's schema: it is then
/// never installed. The leaf's own `defaultValue` is installed instead when
/// it has one, and otherwise nothing, so booting never fails over it.
fn usable_default(
    spec: &nix_secrets_core::SecretSpec,
    identifier: &str,
    value: Vec<u8>,
    version: &str,
) -> Option<(Vec<u8>, String)> {
    let hosts = spec.ssh_hosts();
    let port = spec.expected_ssh_port.unwrap_or(0);
    let error = match std::str::from_utf8(&value) {
        Ok(text) => match nix_secrets_core::schema::validate_ssh_known_hosts(text, &hosts, port) {
            Ok(()) => return Some((value, version.to_owned())),
            Err(error) => error,
        },
        Err(_) => "it is not UTF-8".to_owned(),
    };
    let fallback = spec.default_value.as_deref().filter(|default| {
        nix_secrets_core::schema::validate_ssh_known_hosts(default, &hosts, port).is_ok()
    });
    eprintln!(
        "secret-deploy: the stored public information for {identifier} is invalid under this host's schema and is not installed ({error}); {}",
        if fallback.is_some() {
            "installing its defaultValue instead"
        } else {
            "it stays absent until it is republished"
        }
    );
    fallback.map(|default| {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(default.as_bytes());
        (
            default.as_bytes().to_vec(),
            digest.iter().map(|byte| format!("{byte:02x}")).collect(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

    fn spec(default: Option<&str>) -> nix_secrets_core::SecretSpec {
        let mut leaf = serde_json::json!({
            "kind": "public-info", "recipientPublicKeys": [], "recipientIds": [], "consumerUnits": [],
            "sharedPublicId": "reporting/receiver-known-hosts", "expectedSshHost": "report.example",
            "expectedSshPort": 22, "installDefaultIfMissing": true,
            "destination": {"path": "/persistent/public-info/reporting/receiver-known-hosts",
                "category": "public-info", "owner": "root", "group": "root", "mode": "0644",
                "contentType": "ssh-known-hosts"}
        });
        if let Some(default) = default {
            leaf["defaultValue"] = serde_json::json!(default);
        }
        let schema = Schema::from_json(
            &serde_json::json!({"host": {
                "metadata": {"socketPath": "/run/unused",
                    "deployment": {"host": "host", "destination": "forward@host", "port": 22}},
                "services": {"reporting-trust": {"receiver-known-hosts": leaf}}
            }})
            .to_string(),
        )
        .unwrap();
        schema
            .secret(&SecretPath::parse("host.services.reporting-trust.receiver-known-hosts").unwrap())
            .unwrap()
    }

    /// The store's record, baked in as the boot-time default, predates the
    /// host list this host runs now.
    #[test]
    fn a_stale_stored_default_is_never_installed_and_never_fails_boot() {
        let stale = format!("ns1.lamk.eu {KEY}\nreport.example {KEY}\n").into_bytes();
        let valid = format!("report.example {KEY}\n");
        assert_eq!(
            usable_default(&spec(None), "id", valid.clone().into_bytes(), "ab"),
            Some((valid.clone().into_bytes(), "ab".into()))
        );
        assert_eq!(usable_default(&spec(None), "id", stale.clone(), "ab"), None);
        let (value, version) = usable_default(&spec(Some(&valid)), "id", stale, "ab").unwrap();
        assert_eq!(value, valid.as_bytes());
        assert_eq!(version.len(), 64);
    }
}
