use super::*;

impl SecretStore {
    pub fn list_public_info(&self) -> Result<BTreeMap<String, PublicInfoRecord>, StoreError> {
        self.with_lock(false, |document| Ok(document.public_info.clone()))
    }

    pub fn get_public_info(&self, shared_id: &str) -> Result<Option<PublicInfoRecord>, StoreError> {
        self.with_lock(false, |document| {
            Ok(document.public_info.get(shared_id).cloned())
        })
    }

    pub fn set_public_info_if_version(
        &self,
        schema: &Schema,
        path: &SecretPath,
        value: PublicInfoRecord,
        expected_version: Option<&str>,
    ) -> Result<(), StoreError> {
        let crate::schema::SecretSpec {
            kind: SecretKind::PublicInfo,
            shared_public_id: Some(id),
            expected_ssh_host: Some(host),
            expected_ssh_port: Some(port),
            ..
        } = schema.secret(path)?
        else {
            return Err(StoreError::InvalidPublicInfo);
        };
        if value.version_id.len() != 32
            || !value.version_id.bytes().all(|b| b.is_ascii_hexdigit())
            || validate_ssh_known_hosts(&value.value, &host, port).is_err()
        {
            return Err(StoreError::InvalidPublicInfo);
        }
        self.with_lock(true, |document| {
            let old = document
                .public_info
                .get(&id)
                .map(|record| record.version_id.as_str());
            if old != expected_version {
                return Err(StoreError::VersionConflict);
            }
            document.public_info.insert(id, value);
            Ok(())
        })
    }

    pub fn remove_public_info_if_version(
        &self,
        schema: &Schema,
        path: &SecretPath,
        expected_version: &str,
    ) -> Result<bool, StoreError> {
        let crate::schema::SecretSpec {
            kind: SecretKind::PublicInfo,
            shared_public_id: Some(id),
            ..
        } = schema.secret(path)?
        else {
            return Err(StoreError::InvalidPublicInfo);
        };
        self.with_lock(true, |document| {
            if document
                .public_info
                .get(&id)
                .map(|record| record.version_id.as_str())
                != Some(expected_version)
            {
                return Err(StoreError::VersionConflict);
            }
            Ok(document.public_info.remove(&id).is_some())
        })
    }
}
