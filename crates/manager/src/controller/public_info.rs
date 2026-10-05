use super::*;
use nix_secrets_core::{PublicInfoRecord, SecretKind};

impl Controller {
    pub(super) fn materialize_host_defaults(
        &mut self,
        requested: &[String],
        host_defaults: &[String],
    ) -> Result<(), String> {
        let selected = selected_host_defaults(requested, host_defaults, |identifier| {
            let path = SecretPath::parse(identifier).map_err(|e| e.to_string())?;
            let spec = self.public_spec(&path)?.ok_or("host default is not public information")?;
            let id = spec.shared_public_id.clone().ok_or("host default has no shared ID")?;
            Ok((id, (path, spec)))
        })?;
        for (path, spec) in selected {
            self.materialize_public_default(&path, &spec)?;
        }
        Ok(())
    }

    /// Called only while fulfilling an approved deployment, never while browsing.
    pub(super) fn materialize_public_default(
        &mut self,
        path: &SecretPath,
        spec: &nix_secrets_core::SecretSpec,
    ) -> Result<PublicInfoRecord, String> {
        let id = spec.shared_public_id.as_deref().ok_or("public info has no shared ID")?;
        if let Some(record) = self.client.get_public_info(id).map_err(|e| e.to_string())? {
            return Ok(record);
        }
        let record = default_record(spec).ok_or("required public info is unset")?;
        nix_secrets_core::schema::validate_ssh_known_hosts(
            &record.value, &spec.ssh_hosts(), spec.expected_ssh_port.ok_or("missing expected SSH port")?,
        ).map_err(str::to_owned)?;
        let write = self.client.set_public_info_if_version(path, record.clone(), None);
        let stored = self.client.get_public_info(id).map_err(|e| e.to_string())?;
        materialized_result(record, write.map_err(|e| format!("materializing public-info default {path} (shared ID {id}): {e}")), stored)
    }

    pub(super) fn public_spec(
        &self,
        path: &SecretPath,
    ) -> Result<Option<nix_secrets_core::SecretSpec>, String> {
        match self.schema.leaf(path).map_err(|error| error.to_string())? {
            LeafSpec::Stored(spec) if matches!(spec.kind, SecretKind::PublicInfo) => Ok(Some(spec)),
            _ => Ok(None),
        }
    }

    pub(super) fn save_public_info(
        &mut self,
        path: &SecretPath,
        value: &[u8],
    ) -> Result<(), String> {
        let spec = self.public_spec(path)?.ok_or("not a public-info leaf")?;
        let id = spec
            .shared_public_id
            .clone()
            .ok_or("public-info has no shared ID")?;
        let text = std::str::from_utf8(value).map_err(|_| "public info is not UTF-8")?;
        nix_secrets_core::schema::validate_ssh_known_hosts(
            text,
            &spec.ssh_hosts(),
            spec.expected_ssh_port.ok_or("missing expected SSH port")?,
        )
        .map_err(str::to_owned)?;
        let expected = self
            .client
            .get_public_info(&id)
            .map_err(|error| error.to_string())?
            .map(|record| record.version_id);
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| "cannot generate public-info version")?;
        let version_id = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let record = PublicInfoRecord {
            version_id,
            value: text.into(),
        };
        self.client
            .set_public_info_if_version(path, record.clone(), expected)
            .map_err(|error| error.to_string())?;
        if self
            .client
            .get_public_info(&id)
            .map_err(|error| error.to_string())?
            != Some(record)
        {
            return Err("public-info save failed read-back verification".into());
        }
        Ok(())
    }

    pub(super) fn reveal_public_info(
        &mut self,
        path: &SecretPath,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let id = self
            .public_spec(path)?
            .ok_or("not a public-info leaf")?
            .shared_public_id
            .ok_or("missing shared ID")?;
        let record = self
            .client
            .get_public_info(&id)
            .map_err(|error| error.to_string())?
            .ok_or("public info is unset")?;
        Ok(Zeroizing::new(record.value.into_bytes()))
    }

    pub(super) fn delete_public_info(&mut self, path: &SecretPath) -> Result<(), String> {
        let id = self
            .public_spec(path)?
            .ok_or("not a public-info leaf")?
            .shared_public_id
            .ok_or("missing shared ID")?;
        let old = self
            .client
            .get_public_info(&id)
            .map_err(|error| error.to_string())?
            .ok_or("public info is unset")?;
        self.client
            .remove_public_info_if_version(path, old.version_id)
            .map_err(|error| error.to_string())?
            .then_some(())
            .ok_or_else(|| "public info is already unset".into())
    }
}

impl Controller {
    /// What [`super::unset::plan_unset`] treats as set for `identifiers`:
    /// every stored value, and each requested public-information leaf whose
    /// shared value is stored.
    pub(super) fn plan_set(
        &mut self,
        identifiers: &[String],
    ) -> Result<std::collections::BTreeSet<String>, String> {
        let mut set = self
            .client
            .list()
            .map_err(|error| error.to_string())?
            .into_keys()
            .collect::<std::collections::BTreeSet<_>>();
        let public = self
            .client
            .list_public_info()
            .map_err(|error| error.to_string())?;
        for identifier in identifiers {
            let Ok(path) = SecretPath::parse(identifier) else {
                continue;
            };
            if let Ok(LeafSpec::Stored(spec)) = self.schema.leaf(&path) {
                if spec.default_value.is_some()
                    || spec
                        .shared_public_id
                        .as_ref()
                        .is_some_and(|id| public.contains_key(id))
                {
                    set.insert(identifier.clone());
                }
            }
        }
        Ok(set)
    }
}

/// A public-info leaf's `defaultValue` as a record. Its version is the
/// SHA-256 of the value, as the host's default-install unit names it, so a
/// host that installed the default is not sent it again.
pub(super) fn default_record(
    spec: &nix_secrets_core::SecretSpec,
) -> Option<nix_secrets_core::PublicInfoRecord> {
    use sha2::Digest;
    let value = spec.default_value.clone()?;
    let digest = sha2::Sha256::digest(value.as_bytes());
    let version_id = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Some(nix_secrets_core::PublicInfoRecord { version_id, value })
}

/// Select defaults before the deployment removes host-installed values.
/// Resolve only approved requested identifiers, and publish a shared value once.
fn selected_host_defaults<T>(
    requested: &[String], defaults: &[String],
    mut resolve: impl FnMut(&str) -> Result<(String, T), String>,
) -> Result<Vec<T>, String> {
    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for id in requested.iter().filter(|id| defaults.contains(*id)) {
        let (shared, value) = resolve(id)?;
        if seen.insert(shared) { selected.push(value); }
    }
    Ok(selected)
}

/// A concurrent operator write wins over the schema default. Absence after a
/// rejected write, or a missing read-back after success, is always an error.
fn materialized_result(
    proposed: PublicInfoRecord,
    write: Result<(), String>,
    stored: Option<PublicInfoRecord>,
) -> Result<PublicInfoRecord, String> {
    match (write, stored) {
        (_, Some(record)) => Ok(record),
        (Err(error), None) => Err(error),
        (Ok(()), None) => Err(format!("public default save failed read-back verification for version {}", proposed.version_id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(version: &str) -> PublicInfoRecord {
        PublicInfoRecord { version_id: version.into(), value: "public known-hosts fixture".into() }
    }
    #[test]
    fn host_installed_defaults_are_selected_before_target_exclusion() {
        let requested = vec!["host.public-default".into(), "host.secret".into(), "other.shared-default".into()];
        let defaults = Vec::from(["host.public-default".into(), "other.shared-default".into(), "unrequested.default".into()]);
        let selected = selected_host_defaults(&requested, &defaults, |id| {
            assert_ne!(id, "host.secret");
            assert_ne!(id, "unrequested.default");
            Ok(("shared/public-id".into(), id.to_owned()))
        }).unwrap();
        assert_eq!(selected, ["host.public-default"]);
        let sent = requested.iter().filter(|id| !defaults.contains(*id)).collect::<Vec<_>>();
        assert_eq!(sent, [&"host.secret".to_string()]);
        assert!(!selected.is_empty()); // Host-installed exclusion cannot omit store sync.
    }

    #[test]
    fn materialization_preserves_a_concurrent_explicit_value() {
        let explicit = record("operator-version");
        assert_eq!(materialized_result(record("default-version"), Err("CAS conflict".into()), Some(explicit.clone())).unwrap(), explicit);
        assert_eq!(materialized_result(record("default-version"), Ok(()), Some(explicit.clone())).unwrap(), explicit);
    }
    #[test]
    fn materialization_requires_durable_readback() {
        let default = record("default-version");
        assert_eq!(materialized_result(default.clone(), Ok(()), Some(default.clone())).unwrap(), default);
        assert!(materialized_result(default.clone(), Ok(()), None).is_err());
        assert_eq!(materialized_result(default, Err("write refused".into()), None).unwrap_err(), "write refused");
    }
    #[test]
    fn approved_host_default_is_persisted_with_exact_target_sha256_version() {
        let value = "[box.example]:23 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n";
        let document = serde_json::json!({ "host": {
            "metadata": {"socketPath":"/run/backend.sock", "deployment":{"host":"host", "destination":"forward@host", "port":22}},
            "services": {"backup": {"known-hosts": {
                "kind":"public-info", "sharedPublicId":"storage-box/known-hosts",
                "expectedSshHost":"box.example", "expectedSshPort":23, "defaultValue":value,
                "destination":{"path":"/persistent/public-info/storage-box/known-hosts", "category":"public-info", "owner":"root", "group":"root", "mode":"0644", "contentType":"ssh-known-hosts"},
                "consumerUnits":[]
            }}}
        }});
        let schema = nix_secrets_core::Schema::from_json(&document.to_string()).unwrap();
        let path = SecretPath::parse("host.services.backup.known-hosts").unwrap();
        let spec = schema.secret(&path).unwrap();
        let proposed = default_record(&spec).unwrap();
        assert_eq!(proposed.version_id.len(), 64);
        let dir = tempfile::tempdir().unwrap();
        let store = nix_secrets_core::SecretStore::new(dir.path().join("nix-secrets.toml"));
        let write = store.set_public_info_if_version(&schema, &path, proposed.clone(), None);
        let stored = store.get_public_info("storage-box/known-hosts").unwrap();
        assert_eq!(
            materialized_result(proposed.clone(), write.map_err(|e| e.to_string()), stored)
                .unwrap(),
            proposed
        );
        assert_eq!(
            store
                .get_public_info("storage-box/known-hosts")
                .unwrap()
                .unwrap()
                .value,
            value
        );
    }
}
