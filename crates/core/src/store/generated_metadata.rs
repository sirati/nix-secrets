use super::*;

impl SecretStore {
    pub fn set_generated_public_key_if_version(
        &self,
        schema: &Schema,
        path: &SecretPath,
        value: GeneratedPublicKey,
        expected_version: Option<&str>,
    ) -> Result<(), StoreError> {
        let LeafSpec::Generated(spec) = schema.leaf(path)? else {
            return Err(StoreError::InvalidPublicKey);
        };
        if spec.generated_secret.secret_type != crate::schema::GeneratedSecretType::LocalSshKey
            || !crate::schema::validation::valid_ssh_public_key(&value.public_key)
            || value.version_id.is_empty()
            || value.version_id.len() > 256
        {
            return Err(StoreError::InvalidPublicKey);
        }
        self.with_lock(true, |document| {
            let actual = document.generated_public_keys.get(&path.to_string());
            if actual.map(|record| record.version_id.as_str()) != expected_version {
                return Err(StoreError::VersionConflict);
            }
            if actual.is_some_and(|record| record.public_key != value.public_key) {
                return Err(StoreError::VersionConflict);
            }
            document
                .generated_public_keys
                .insert(path.to_string(), value);
            Ok(())
        })
    }

    pub fn generated_public_key(
        &self,
        path: &SecretPath,
    ) -> Result<Option<GeneratedPublicKey>, StoreError> {
        self.with_lock(false, |document| {
            Ok(document
                .generated_public_keys
                .get(&path.to_string())
                .cloned())
        })
    }

    pub fn set_public_key_if_version(
        &self,
        schema: &Schema,
        path: &SecretPath,
        public_key: String,
        expected_version: &[u8],
    ) -> Result<(), StoreError> {
        let LeafSpec::Generated(spec) = schema.leaf(path)? else {
            return Err(StoreError::InvalidPublicKey);
        };
        if spec.generated_secret.secret_type != crate::schema::GeneratedSecretType::StorageBoxSshKey
            || !crate::schema::validation::valid_ssh_public_key(&public_key)
        {
            return Err(StoreError::InvalidPublicKey);
        }
        self.with_lock(true, |document| {
            let record = document
                .secrets
                .get_mut(&path.to_string())
                .ok_or(StoreError::VersionConflict)?;
            if record.version_id != expected_version {
                return Err(StoreError::VersionConflict);
            }
            if record
                .public_key
                .as_deref()
                .is_some_and(|old| old != public_key)
            {
                return Err(StoreError::VersionConflict);
            }
            record.public_key = Some(public_key);
            Ok(())
        })
    }
}
