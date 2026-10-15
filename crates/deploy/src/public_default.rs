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
    // Fast path for every boot after the first; `install` decides again under the lock.
    if deployer
        .current_versions()?
        .get(identifier)
        .map(String::as_str)
        == Some(version)
    {
        return Ok(());
    }
    let metadata = fs::metadata(source)?;
    if !metadata.is_file()
        || metadata.len() > nix_secrets_core::schema::MAX_KNOWN_HOSTS_BYTES as u64
    {
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
    install(&deployer, &public).map(|_| ())
}

/// What a declared default does to the value installed at its destination.
#[derive(Debug, Eq, PartialEq)]
enum Decision {
    Install,
    Unchanged,
    /// The installed value is an older default this unit installed.
    Replace,
    /// The installed value came from the operator, or its provenance is unknown.
    KeepOperatorValue,
}

/// Directory in the public-info root recording, per identifier, the version
/// this unit last installed. Only such a value is ever replaced. Values
/// installed before the record existed have none and are kept for good.
const PROVENANCE_DIR: &str = ".public-defaults";

fn provenance_path(deployer: &Deployer, identifier: &str) -> std::path::PathBuf {
    deployer
        .root()
        .join(PROVENANCE_DIR)
        .join(sha256_hex(identifier.as_bytes()))
}

/// The version this unit recorded installing at `identifier`. Anything
/// unreadable as such a record counts as none, which keeps the value.
fn installed_by_default(
    deployer: &Deployer,
    identifier: &str,
) -> Result<Option<String>, DeployError> {
    let path = provenance_path(deployer, identifier);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() > 256 {
        return Ok(None);
    }
    Ok(String::from_utf8(fs::read(path)?).ok())
}

/// Records that this unit installed `version` at `identifier`.
fn record_installed_by_default(
    deployer: &Deployer,
    identifier: &str,
    version: &str,
) -> Result<(), DeployError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let directory = deployer.root().join(PROVENANCE_DIR);
    match crate::fsutil::create_directory(&directory, 0o700) {
        Err(DeployError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            crate::fsutil::require_real_directory(&directory, "public default provenance")?
        }
        result => result?,
    }
    let path = provenance_path(deployer, identifier);
    let staged = path.with_extension("new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&staged)?;
    file.write_all(version.as_bytes())?;
    file.sync_all()?;
    fs::rename(&staged, &path)?;
    crate::fsutil::sync_directory(&directory)
}

/// The destination as found under the deployment lock.
#[derive(Debug)]
enum Installed {
    Absent,
    /// Lowercase hex SHA-256 of the file, or `None` when it is not a regular
    /// file of plausible size.
    Present(Option<String>),
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// An installed value is replaced only when this unit recorded installing
/// exactly its version, and the file still holds those contents (defaults
/// are versioned by the SHA-256 of their contents). The version alone proves
/// nothing: anyone deploying may pick any version.
fn decide(
    recorded: Option<&str>,
    installed_by_default: Option<&str>,
    new_version: &str,
    installed: &Installed,
) -> Decision {
    match (recorded, installed) {
        (None, Installed::Absent) => Decision::Install,
        (Some(recorded), _) if recorded == new_version => Decision::Unchanged,
        (Some(recorded), Installed::Present(Some(digest)))
            if installed_by_default == Some(recorded) && digest == recorded =>
        {
            Decision::Replace
        }
        _ => Decision::KeepOperatorValue,
    }
}

fn inspect_installed(path: &Path) -> Result<Installed, DeployError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Installed::Absent),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file()
        || metadata.len() > nix_secrets_core::schema::MAX_KNOWN_HOSTS_BYTES as u64
    {
        return Ok(Installed::Present(None));
    }
    Ok(Installed::Present(Some(sha256_hex(&fs::read(path)?))))
}

/// Installs the single default in `public` unless the decision, taken under
/// the deployment lock, keeps what is installed. Returns that decision.
fn install(
    deployer: &Deployer,
    public: &crate::schema::ResolvedBatch,
) -> Result<Decision, DeployError> {
    let [entry] = public.entries.as_slice() else {
        return Err(DeployError::Invalid(
            "public default did not resolve to one public destination".into(),
        ));
    };
    if entry.class != SecretClass::PublicInfo {
        return Err(DeployError::Invalid(
            "public default is not public information".into(),
        ));
    }
    let mut decision = Decision::Unchanged;
    deployer.deploy_if(
        public,
        |deployer| {
            let versions = deployer.current_versions()?;
            let destination = deployer.secret_path(&entry.service, entry.class, &entry.secret)?;
            decision = decide(
                versions.get(&entry.identifier).map(String::as_str),
                installed_by_default(deployer, &entry.identifier)?.as_deref(),
                &entry.version_id,
                &inspect_installed(&destination)?,
            );
            if decision == Decision::KeepOperatorValue {
                eprintln!(
                    "secret-deploy: {} holds a value this unit did not record installing (operator-deployed, or installed before provenance records existed); keeping it instead of the declared default",
                    entry.identifier
                );
            }
            Ok(matches!(decision, Decision::Install | Decision::Replace))
        },
        // A crash before this record keeps the value for good: fail safe.
        |deployer| record_installed_by_default(deployer, &entry.identifier, &entry.version_id),
    )?;
    Ok(decision)
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
    fallback.map(|default| (default.as_bytes().to_vec(), sha256_hex(default.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

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
            .secret(
                &SecretPath::parse("host.services.reporting-trust.receiver-known-hosts").unwrap(),
            )
            .unwrap()
    }

    const OPERATOR_VERSION: &str = "0123456789abcdef0123456789abcdef";

    fn present(contents: &[u8]) -> Installed {
        Installed::Present(Some(sha256_hex(contents)))
    }

    #[test]
    fn decides_every_provenance_case() {
        let old = b"old default\n";
        let new_version = sha256_hex(b"new default\n");
        let old_version = sha256_hex(old);
        let decide_new = |recorded: Option<&str>, installed: &Installed| {
            decide(recorded, recorded, &new_version, installed)
        };
        assert_eq!(decide_new(None, &Installed::Absent), Decision::Install);
        assert_eq!(
            decide_new(Some(&new_version), &present(b"new default\n")),
            Decision::Unchanged
        );
        assert_eq!(
            decide_new(Some(&old_version), &present(old)),
            Decision::Replace
        );
        // Without this unit's record, a content-hash version proves nothing:
        // the value came from the operator or predates the record.
        assert_eq!(
            decide(Some(&old_version), None, &new_version, &present(old)),
            Decision::KeepOperatorValue
        );
        let other = sha256_hex(b"other\n");
        assert_eq!(
            decide(Some(&old_version), Some(&other), &new_version, &present(old)),
            Decision::KeepOperatorValue
        );
        // An operator value is versioned randomly, never by its content hash.
        assert_eq!(
            decide_new(Some(OPERATOR_VERSION), &present(old)),
            Decision::KeepOperatorValue
        );
        // A content-hash version no longer matching the file is not trusted.
        assert_eq!(
            decide_new(Some(&old_version), &present(b"edited\n")),
            Decision::KeepOperatorValue
        );
        assert_eq!(
            decide_new(Some(&old_version.to_uppercase()), &present(old)),
            Decision::KeepOperatorValue
        );
        assert_eq!(
            decide_new(Some(&old_version), &Installed::Present(None)),
            Decision::KeepOperatorValue
        );
        assert_eq!(
            decide_new(Some(&old_version), &Installed::Absent),
            Decision::KeepOperatorValue
        );
        assert_eq!(decide_new(None, &present(old)), Decision::KeepOperatorValue);
    }

    fn public_batch(contents: &[u8], version: &str) -> crate::schema::ResolvedBatch {
        crate::schema::ResolvedBatch {
            entries: vec![crate::schema::ResolvedSecret {
                identifier: "host.services.reporting-trust.receiver-known-hosts".into(),
                version_id: version.into(),
                service: "reporting".into(),
                class: SecretClass::PublicInfo,
                secret: "receiver-known-hosts".into(),
                contents: contents.into(),
                owner: nix::unistd::geteuid().as_raw(),
                group: nix::unistd::getegid().as_raw(),
                mode: 0o644,
                audit_ssh_user: None,
                audit_key_names: Vec::new(),
            }],
        }
    }

    #[test]
    fn a_changed_default_replaces_a_stale_default_but_never_an_operator_value() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("public-info");
        let deployer = Deployer::at(&root).unwrap();
        let installed = root.join("reporting/receiver-known-hosts");
        let first = format!("report.example {KEY}\n");
        let second = format!("[report.example]:2222 {KEY}\n");

        let deploy_default = |value: &str| {
            install(
                &deployer,
                &public_batch(value.as_bytes(), &sha256_hex(value.as_bytes())),
            )
            .unwrap()
        };
        assert_eq!(deploy_default(&first), Decision::Install);
        assert_eq!(deploy_default(&first), Decision::Unchanged);
        assert_eq!(deploy_default(&second), Decision::Replace);
        assert_eq!(fs::read_to_string(&installed).unwrap(), second);

        let operator = format!("operator.example {KEY}\n");
        deployer
            .deploy(&public_batch(operator.as_bytes(), OPERATOR_VERSION))
            .unwrap();
        assert_eq!(deploy_default(&first), Decision::KeepOperatorValue);
        assert_eq!(fs::read_to_string(&installed).unwrap(), operator);
        assert_eq!(
            deployer.current_versions().unwrap()
                ["host.services.reporting-trust.receiver-known-hosts"],
            OPERATOR_VERSION
        );
    }

    /// The operator may deliver a value versioned exactly like a default,
    /// and values installed before provenance records existed carry no
    /// record. Neither is ever replaced.
    #[test]
    fn a_default_never_replaces_a_value_it_did_not_record_installing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("public-info");
        let deployer = Deployer::at(&root).unwrap();
        let installed = root.join("reporting/receiver-known-hosts");
        let declared = format!("report.example {KEY}\n");
        let deploy_default = || {
            install(
                &deployer,
                &public_batch(declared.as_bytes(), &sha256_hex(declared.as_bytes())),
            )
            .unwrap()
        };

        let operator = format!("operator.example {KEY}\n");
        deployer
            .deploy(&public_batch(
                operator.as_bytes(),
                &sha256_hex(operator.as_bytes()),
            ))
            .unwrap();
        assert_eq!(deploy_default(), Decision::KeepOperatorValue);
        assert_eq!(fs::read_to_string(&installed).unwrap(), operator);

        // After this unit installed a default, the operator redeploys it
        // with a content-hash version: the record no longer matches.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("public-info");
        let deployer = Deployer::at(&root).unwrap();
        let installed = root.join("reporting/receiver-known-hosts");
        let deploy_default = |value: &str| {
            install(
                &deployer,
                &public_batch(value.as_bytes(), &sha256_hex(value.as_bytes())),
            )
            .unwrap()
        };
        assert_eq!(deploy_default(&operator), Decision::Install);
        deployer
            .deploy(&public_batch(
                declared.as_bytes(),
                &sha256_hex(declared.as_bytes()),
            ))
            .unwrap();
        let next = format!("[report.example]:2222 {KEY}\n");
        assert_eq!(deploy_default(&next), Decision::KeepOperatorValue);
        assert_eq!(fs::read_to_string(&installed).unwrap(), declared);
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
        let loopback = format!("127.0.0.1 {KEY}\nreport.example {KEY}\n").into_bytes();
        assert_eq!(usable_default(&spec(None), "id", loopback, "ab"), None);
        let (value, version) = usable_default(&spec(Some(&valid)), "id", stale, "ab").unwrap();
        assert_eq!(value, valid.as_bytes());
        assert_eq!(version.len(), 64);
    }
}
