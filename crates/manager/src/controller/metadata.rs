use super::*;
use nix_secrets_core::{GeneratedPublicKey, GeneratedSecretType};

impl Controller {
    pub(super) fn save_generated_public_key(
        &mut self,
        path: &SecretPath,
        kind: GeneratedSecretType,
        public_key: &str,
    ) -> Result<(), String> {
        let key = ssh_key::PublicKey::from_openssh(public_key)
            .map_err(|_| "target returned an invalid SSH public key")?;
        if key.algorithm() != ssh_key::Algorithm::Ed25519 {
            return Err("target returned a non-Ed25519 SSH public key".into());
        }
        let canonical = key.to_openssh().map_err(|error| error.to_string())?;
        match kind {
            GeneratedSecretType::LocalSshKey => {
                let old = self
                    .client
                    .generated_public_key(path)
                    .map_err(|e| e.to_string())?;
                // This receipt comes from the approved, authenticated target.
                // A fresh host generates a new local key; metadata follows it
                // using CAS instead of permanently binding the first key.
                let value = GeneratedPublicKey {
                    version_id: format!(
                        "local-generated-{}",
                        key.fingerprint(ssh_key::HashAlg::Sha256)
                    ),
                    public_key: canonical,
                };
                if old.as_ref() == Some(&value) {
                    return Ok(());
                }
                self.client
                    .set_generated_public_key_if_version(
                        path,
                        value.clone(),
                        old.map(|record| record.version_id),
                    )
                    .map_err(|e| e.to_string())?;
                let saved = self
                    .client
                    .generated_public_key(path)
                    .map_err(|e| e.to_string())?;
                if saved != Some(value) {
                    return Err("generated public key failed read-back verification".into());
                }
            }
            GeneratedSecretType::StorageBoxSshKey => {
                let old =
                    self.client.get(path).map_err(|e| e.to_string())?.ok_or(
                        "Storage Box bootstrap secret disappeared before key registration",
                    )?;
                if old.public_key.as_deref() == Some(canonical.as_str()) {
                    return Ok(());
                }
                self.client
                    .set_public_key_if_version(
                        path,
                        canonical.clone(),
                        old.version_id.clone(),
                        old.public_key.clone(),
                    )
                    .map_err(|e| e.to_string())?;
                let saved = self
                    .client
                    .get(path)
                    .map_err(|e| e.to_string())?
                    .ok_or("Storage Box bootstrap secret disappeared after key registration")?;
                if saved.version_id != old.version_id
                    || saved.public_key.as_deref() != Some(canonical.as_str())
                {
                    return Err("generated public key failed read-back verification".into());
                }
            }
        }
        Ok(())
    }
}
