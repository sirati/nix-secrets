//! Operator-only values: keypair generation and public key access.

use super::*;
use nix_secrets_core::OperatorSpec;

impl Controller {
    fn operator_spec(&self, path: &SecretPath) -> Result<OperatorSpec, String> {
        match self.schema.leaf(path).map_err(|error| error.to_string())? {
            LeafSpec::Operator(spec) => Ok(spec),
            _ => Err(format!("{path} is not an operator leaf")),
        }
    }

    /// Runs the leaf's generator, encrypts the private key to its recipients,
    /// and stores the public key beside the ciphertext in one write.
    pub fn generate_keypair(&mut self, path: &str) -> Result<(), String> {
        let path = SecretPath::parse(path).map_err(|error| error.to_string())?;
        let spec = self.operator_spec(&path)?;
        let generator = spec
            .generator
            .as_ref()
            .ok_or_else(|| format!("{path} declares no generator"))?;
        let pair = (self.keypair_runner)(generator)?;
        self.store_keypair(&path, &spec, &pair)
    }

    pub(crate) fn store_keypair(
        &mut self,
        path: &SecretPath,
        spec: &OperatorSpec,
        pair: &crate::keypair::Keypair,
    ) -> Result<(), String> {
        let recipients = spec
            .recipient_ids
            .iter()
            .zip(&spec.recipient_public_keys)
            .map(|(id, key)| Recipient {
                id,
                ssh_public_key: key,
            })
            .collect::<Vec<_>>();
        let public = STANDARD.encode(&pair.public);
        let version = self
            .client
            .set_private_key(
                path,
                &pair.private,
                &recipients,
                &self.provider,
                public.clone(),
            )
            .map_err(|error| error.to_string())?;
        let stored = self
            .client
            .get(path)
            .map_err(|error| error.to_string())?
            .ok_or("operator key disappeared after save")?;
        if stored.version_id != version || stored.public_key.as_deref() != Some(public.as_str()) {
            return Err("operator key failed read-back verification".into());
        }
        Ok(())
    }

    /// Decrypts one stored value for `pipe-secret`. Public information has
    /// no ciphertext and is refused, so the command only ever handles secrets.
    pub fn reveal_secret(
        &mut self,
        identifier: &str,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
        match self.schema.leaf(&path).map_err(|error| error.to_string())? {
            LeafSpec::Stored(spec) if matches!(spec.kind, SecretKind::PublicInfo) => {
                return Err(format!("{identifier} is public information, not a secret"))
            }
            _ => {}
        }
        let record = self
            .client
            .get(&path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("{identifier} is unset"))?;
        let envelope = EncryptedSecret {
            format_version: record.format_version,
            version_id: record.version_id,
            recipient_ids: record.recipient_ids,
            age_ciphertext: record.age_ciphertext,
        };
        decrypt_secret(identifier, &envelope, &self.provider).map_err(|error| error.to_string())
    }

    /// The raw public key stored with an operator key.
    pub(super) fn operator_public_key(&mut self, path: &SecretPath) -> Result<Vec<u8>, String> {
        let record = self
            .client
            .get(path)
            .map_err(|error| error.to_string())?
            .ok_or("operator key is unset")?;
        let public = record
            .public_key
            .ok_or("this operator key has no public key; generate it with g")?;
        STANDARD
            .decode(public)
            .map_err(|_| "stored operator public key is not base64".into())
    }
}
