use super::*;
use nix_secrets_core::{PublicInfoRecord, SecretKind};

impl Controller {
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
            .ok_or("public-info has no shared ID")?;
        let text = std::str::from_utf8(value).map_err(|_| "public info is not UTF-8")?;
        nix_secrets_core::schema::validate_ssh_known_hosts(
            text,
            spec.expected_ssh_host
                .as_deref()
                .ok_or("missing expected SSH host")?,
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
                if spec
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
