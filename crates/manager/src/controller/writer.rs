mod approval;
mod generation;
mod private_key;
use super::generate::{generate_compatible, validate_password_value};
use super::*;

impl SecretWriter for Controller {
    fn refresh_profiles(&mut self) -> Result<Option<ProfileSnapshot>, String> {
        if self.background.is_some() {
            self.drain_background();
            return Ok(self.pending_profiles.take());
        }
        self.client
            .list_profiles()
            .map(Some)
            .map_err(|error| error.to_string())
    }

    fn save_profile(
        &mut self,
        name: String,
        profile: ViewProfile,
        revision: u64,
    ) -> Result<ProfileSnapshot, String> {
        self.client
            .save_profile(name, profile, revision)
            .map_err(|error| error.to_string())
    }

    fn delete_profile(&mut self, name: String, revision: u64) -> Result<ProfileSnapshot, String> {
        self.client
            .delete_profile(name, revision)
            .map_err(|error| error.to_string())
    }
    fn refresh_rows(&mut self) -> Result<Option<Vec<Row>>, String> {
        if self.background.is_some() {
            self.drain_background();
            if let Some(error) = self.background_error.take() {
                return Err(format!("background refresh stopped: {error}"));
            }
            return Ok(self.pending_rows.take());
        }
        self.rows().map(Some).map_err(|error| error.to_string())
    }
    fn copy_public(&mut self, path: &str) -> Result<(), String> {
        let parsed = SecretPath::parse(path).map_err(|error| error.to_string())?;
        let LeafSpec::Stored(spec) = self
            .schema
            .leaf(&parsed)
            .map_err(|error| error.to_string())?
        else {
            return Err("select a stored OpenSSH private key".into());
        };
        if spec.destination.content_type.as_deref() != Some("openssh-private-key") {
            return Err("selected item is not an OpenSSH private key".into());
        }
        let record = self
            .client
            .get(&parsed)
            .map_err(|error| error.to_string())?
            .ok_or("secret is unset")?;
        let public = record
            .public_key
            .ok_or("public key metadata is missing; replace the private key to derive it")?;
        ssh_key::PublicKey::from_openssh(&public)
            .map_err(|_| "stored public key metadata is invalid")?;
        self.copy(public.as_bytes())
    }
    fn reveal(&mut self, path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let path = SecretPath::parse(path).map_err(|error| error.to_string())?;
        if self.public_spec(&path)?.is_some() {
            return self.reveal_public_info(&path);
        }
        if !matches!(
            self.schema.leaf(&path).map_err(|error| error.to_string())?,
            LeafSpec::Stored(_) | LeafSpec::Generated(_)
        ) {
            return Err("not a stored secret".into());
        }
        let record = self
            .client
            .get(&path)
            .map_err(|error| error.to_string())?
            .ok_or("secret is unset")?;
        let envelope = EncryptedSecret {
            format_version: record.format_version,
            version_id: record.version_id,
            recipient_ids: record.recipient_ids,
            age_ciphertext: record.age_ciphertext,
        };
        decrypt_secret(&path.to_string(), &envelope, &self.provider)
            .map_err(|error| error.to_string())
    }

    fn delete(&mut self, path: &str) -> Result<(), String> {
        let path = SecretPath::parse(path).map_err(|error| error.to_string())?;
        if self.public_spec(&path)?.is_some() {
            return self.delete_public_info(&path);
        }
        let record = self
            .client
            .get(&path)
            .map_err(|error| error.to_string())?
            .ok_or("secret is already unset")?;
        self.client
            .remove_if_version(&path, record.version_id)
            .map_err(|error| error.to_string())?
            .then_some(())
            .ok_or_else(|| "secret is already unset".into())
    }
    fn generate(&mut self, path: &str, kind: GenerateKind) -> Result<Zeroizing<Vec<u8>>, String> {
        let path = SecretPath::parse(path).map_err(|error| error.to_string())?;
        let leaf = self.schema.leaf(&path).map_err(|error| error.to_string())?;
        let (value_type, constraints, external_input_required) = match leaf {
            LeafSpec::Stored(spec) => (
                spec.value_type,
                spec.consumer_constraints,
                spec.external_input_required,
            ),
            LeafSpec::Generated(spec) => (
                spec.value_type,
                spec.consumer_constraints,
                spec.external_input_required,
            ),
        };
        if external_input_required {
            return Err("this value must be supplied from the external system".into());
        }
        if value_type != Some(ValueType::Password) {
            return Err(format!("{path} is not a password leaf"));
        }
        generate_compatible(kind, constraints.as_ref())
    }

    fn copy(&mut self, value: &[u8]) -> Result<(), String> {
        crate::clipboard::copy(value)
    }
    fn paste(&mut self) -> Result<Zeroizing<Vec<u8>>, String> {
        crate::clipboard::paste()
    }
    fn commit_state(&mut self, path: &str) -> nix_secrets_core::CommitState {
        let result = SecretPath::parse(path)
            .map_err(|error| error.to_string())
            .and_then(|path| {
                self.client
                    .commit_state(&path)
                    .map_err(|error| error.to_string())
            });
        result.unwrap_or_else(|reason| nix_secrets_core::CommitState::Unknown { reason })
    }

    fn write(
        &mut self,
        path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        let parsed = match SecretPath::parse(path) {
            Ok(parsed) => parsed,
            Err(error) => return Err((error.to_string(), value)),
        };
        let spec = match self.schema.leaf(&parsed) {
            Ok(spec) => spec,
            Err(error) => return Err((error.to_string(), value)),
        };
        if matches!(&spec, LeafSpec::Stored(leaf) if matches!(leaf.kind, nix_secrets_core::SecretKind::PublicInfo))
        {
            return match self.save_public_info(&parsed, &value) {
                Ok(()) => Ok(Action::Saved(parsed.to_string())),
                Err(error) => Err((error, value)),
            };
        }
        let (value_type, constraints) = match &spec {
            LeafSpec::Stored(spec) => (spec.value_type, spec.consumer_constraints.as_ref()),
            LeafSpec::Generated(spec) => (spec.value_type, spec.consumer_constraints.as_ref()),
        };
        if let Err(error) = validate_password_value(value_type, constraints, &value) {
            return Err((error, value));
        }
        if let LeafSpec::Stored(spec) = &spec {
            if let Err(error) =
                super::ssh_validation::validate(spec.destination.content_type.as_deref(), &value)
            {
                return Err((error, value));
            }
        }
        let (recipient_ids, recipient_public_keys) = match &spec {
            LeafSpec::Stored(spec) => (&spec.recipient_ids, &spec.recipient_public_keys),
            LeafSpec::Generated(spec) => (&spec.recipient_ids, &spec.recipient_public_keys),
        };
        let recipients = recipient_ids
            .iter()
            .zip(recipient_public_keys)
            .map(|(id, key)| Recipient {
                id,
                ssh_public_key: key,
            })
            .collect::<Vec<_>>();
        let result = match &spec {
            LeafSpec::Stored(spec)
                if spec.destination.content_type.as_deref() == Some("openssh-private-key") =>
            {
                let public = match super::ssh_validation::derive_public(
                    spec.destination.content_type.as_deref(),
                    &value,
                ) {
                    Ok(Some(public)) => public,
                    Ok(None) => {
                        return Err(("OpenSSH public derivation is unavailable".into(), value))
                    }
                    Err(error) => return Err((error, value)),
                };
                self.save_private_key(&parsed, &value, &recipients, public)
            }
            _ => self
                .client
                .set(&parsed, &value, &recipients, &self.provider)
                .map_err(|error| error.to_string()),
        };
        match result {
            Ok(()) => Ok(Action::Saved(parsed.to_string())),
            Err(error) => Err((error, value)),
        }
    }

    fn poll_approval(&mut self) -> Result<Option<UiApproval>, String> {
        self.poll_approval_inner()
    }
    fn approval(&mut self, accepted: bool) -> Result<Option<UiApproval>, String> {
        self.approval_inner(accepted)
    }
}
