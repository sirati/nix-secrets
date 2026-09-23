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
                if old
                    .as_ref()
                    .is_some_and(|value| value.public_key != canonical)
                {
                    return Err("generated public key changed unexpectedly".into());
                }
                let value = GeneratedPublicKey {
                    version_id: "local-generated-v1".into(),
                    public_key: canonical,
                };
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
                if old
                    .public_key
                    .as_ref()
                    .is_some_and(|value| value != &canonical)
                {
                    return Err("generated public key changed unexpectedly".into());
                }
                self.client
                    .set_public_key_if_version(path, canonical.clone(), old.version_id.clone())
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
