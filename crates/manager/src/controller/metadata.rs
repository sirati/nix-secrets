use super::host_mutations::{HostMutation, HostMutationBatch};
use super::*;
use nix_secrets_core::{GeneratedPublicKey, GeneratedSecretType};

impl Controller {
    pub(super) fn stage_generated_public_key(
        &mut self,
        path: &SecretPath,
        kind: GeneratedSecretType,
        public_key: &str,
        batch: &mut HostMutationBatch,
    ) -> Result<(), String> {
        let key = ssh_key::PublicKey::from_openssh(public_key)
            .map_err(|_| "target returned an invalid SSH public key")?;
        if key.algorithm() != ssh_key::Algorithm::Ed25519 {
            return Err("target returned a non-Ed25519 SSH public key".into());
        }
        // Strip comments before comparing or persisting key material.
        let canonical = key
            .to_openssh()
            .map_err(|e| e.to_string())?
            .split_ascii_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        match kind {
            GeneratedSecretType::LocalSshKey => {
                let previous = self
                    .client
                    .generated_public_key(path)
                    .map_err(|e| e.to_string())?;
                if previous.as_ref().is_some_and(|old| {
                    ssh_key::PublicKey::from_openssh(&old.public_key)
                        .ok()
                        .is_some_and(|old| old.key_data() == key.key_data())
                }) {
                    return Ok(());
                }
                let proposed = GeneratedPublicKey {
                    version_id: format!(
                        "local-generated-{}",
                        key.fingerprint(ssh_key::HashAlg::Sha256)
                    ),
                    public_key: canonical,
                };
                batch.mutations.push(HostMutation::Generated {
                    path: path.clone(),
                    previous,
                    proposed,
                });
            }
            GeneratedSecretType::StorageBoxSshKey => {
                let old =
                    self.client.get(path).map_err(|e| e.to_string())?.ok_or(
                        "Storage Box bootstrap secret disappeared before key registration",
                    )?;
                if old.public_key.as_ref().is_some_and(|old| {
                    ssh_key::PublicKey::from_openssh(old)
                        .ok()
                        .is_some_and(|old| old.key_data() == key.key_data())
                }) {
                    return Ok(());
                }
                batch.mutations.push(HostMutation::Attached {
                    path: path.clone(),
                    version: old.version_id,
                    previous: old.public_key,
                    proposed: canonical,
                });
            }
        }
        Ok(())
    }
}
