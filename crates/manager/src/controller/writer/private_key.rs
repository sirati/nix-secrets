use super::*;

impl Controller {
    pub(super) fn save_private_key(
        &mut self,
        path: &SecretPath,
        private: &[u8],
        recipients: &[Recipient<'_>],
        public: String,
    ) -> Result<(), String> {
        let version = self
            .client
            .set_private_key(path, private, recipients, &self.provider, public.clone())
            .map_err(|error| error.to_string())?;
        let stored = self
            .client
            .get(path)
            .map_err(|error| error.to_string())?
            .ok_or("private key record disappeared after save")?;
        if stored.version_id != version || stored.public_key.as_deref() != Some(public.as_str()) {
            return Err("private/public key record failed read-back verification".into());
        }
        let envelope = EncryptedSecret {
            format_version: stored.format_version,
            version_id: stored.version_id,
            recipient_ids: stored.recipient_ids,
            age_ciphertext: stored.age_ciphertext,
        };
        let decrypted = decrypt_secret(&path.to_string(), &envelope, &self.provider)
            .map_err(|error| error.to_string())?;
        let derived =
            super::ssh_validation::derive_public(Some("openssh-private-key"), &decrypted)?;
        if decrypted.as_slice() != private || derived.as_deref() != Some(public.as_str()) {
            return Err("stored private key does not match public metadata".into());
        }
        Ok(())
    }
}
