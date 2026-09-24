use super::generate::{generate_compatible, validate_password_value};
use super::*;

impl Controller {
    pub(crate) fn generate_missing_password(
        &mut self,
        path: &str,
        kind: GenerateKind,
    ) -> Result<(), String> {
        let parsed = SecretPath::parse(path).map_err(|error| error.to_string())?;
        let leaf = self
            .schema
            .leaf(&parsed)
            .map_err(|error| error.to_string())?;
        let (value_type, constraints, ids, keys, external_input_required) = match leaf {
            LeafSpec::Stored(spec) => (
                spec.value_type,
                spec.consumer_constraints,
                spec.recipient_ids,
                spec.recipient_public_keys,
                spec.external_input_required,
            ),
            LeafSpec::Generated(spec) => (
                spec.value_type,
                spec.consumer_constraints,
                spec.recipient_ids,
                spec.recipient_public_keys,
                spec.external_input_required,
            ),
        };
        if external_input_required {
            return Err("this value must be supplied from the external system".into());
        }
        if value_type != Some(ValueType::Password) {
            return Err("not a password leaf".into());
        }
        let value = generate_compatible(kind, constraints.as_ref())?;
        let recipients = ids
            .iter()
            .zip(keys.iter())
            .map(|(id, key)| Recipient {
                id,
                ssh_public_key: key,
            })
            .collect::<Vec<_>>();
        self.client
            .set_if_version(&parsed, &value, &recipients, &self.provider, None)
            .map_err(|error| error.to_string())
    }
}

impl SecretWriter for Controller {
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
        self.drain_background();
        if let Some(active) = &self.active {
            if active.renewed_at.elapsed() < Duration::from_secs(60) {
                return Ok(None);
            }
            let id = active.request.id.clone();
            let lease_id = active.lease_id;
            if let Err(error) = self.client.renew(id, lease_id) {
                self.active.take();
                return Err(format!("approval lease was lost: {error}"));
            }
            self.active
                .as_mut()
                .expect("approval remains active")
                .renewed_at = Instant::now();
            return Ok(None);
        }
        if self.background.is_some() && !std::mem::take(&mut self.approvals_ready) {
            return Ok(None);
        }
        let Some((request, lease_id)) = self
            .client
            .poll_and_claim()
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let set = self
            .client
            .list()
            .map_err(|error| error.to_string())?
            .into_keys()
            .collect::<BTreeSet<_>>();
        let mut details = match self.approval_details(&request, None, &set) {
            Ok(details) => details,
            Err(error) => {
                self.client
                    .resolve(request.id, lease_id, false)
                    .map_err(|resolve| resolve.to_string())?;
                return Err(error);
            }
        };
        let host = match self.schema.0.get(&request.target) {
            Some(host) => host,
            None => {
                self.client
                    .resolve(request.id, lease_id, false)
                    .map_err(|e| e.to_string())?;
                return Err("target host is absent from schema".into());
            }
        };
        let connection = Connection {
            destination: host.metadata.deployment.destination.clone(),
            host: host.metadata.deployment.host.clone(),
            port: host.metadata.deployment.port,
            known_hosts: self.known_hosts.clone(),
        };
        let expected = match expected_target(&self.schema, &request) {
            Ok(expected) => expected,
            Err(error) => {
                self.client
                    .resolve(request.id, lease_id, false)
                    .map_err(|e| e.to_string())?;
                return Err(error);
            }
        };
        let host_key = match deployment::preflight(&connection) {
            Ok(preflight) => preflight,
            Err(error) => {
                self.client
                    .resolve(request.id, lease_id, false)
                    .map_err(|e| e.to_string())?;
                return Err(error);
            }
        };
        let known = host_key.status == HostKeyStatus::Known;
        details.host_key = deployment::unknown_description(&host_key);
        self.active = Some(ActiveApproval {
            request,
            lease_id,
            connection,
            expected,
            identity: host_key.identity,
            prepared: None,
            target_approved: known,
            renewed_at: Instant::now(),
        });
        if known {
            if let Err(error) = self.prepare_active() {
                let active = self.active.take().expect("active approval exists");
                self.client
                    .resolve(active.request.id, active.lease_id, false)
                    .map_err(|resolve| resolve.to_string())?;
                return Err(error);
            }
            let active = self.active.as_ref().expect("active approval exists");
            details = self.approval_details(
                &active.request,
                active.prepared.as_ref().map(PreparedDeployment::state),
                &set,
            )?;
        }
        Ok(Some(details))
    }

    fn approval(&mut self, accepted: bool) -> Result<Option<UiApproval>, String> {
        if accepted {
            if !self
                .active
                .as_ref()
                .ok_or("no claimed approval request")?
                .target_approved
            {
                self.prepare_active()?;
                let active = self.active.as_mut().expect("active approval exists");
                active.target_approved = true;
                let request = active.request.clone();
                let state = active
                    .prepared
                    .as_ref()
                    .map(PreparedDeployment::state)
                    .cloned();
                let set = self
                    .client
                    .list()
                    .map_err(|error| error.to_string())?
                    .into_keys()
                    .collect::<BTreeSet<_>>();
                return self
                    .approval_details(&request, state.as_ref(), &set)
                    .map(Some);
            }
            let (id, lease_id) = self
                .active
                .as_ref()
                .map(|active| (active.request.id.clone(), active.lease_id))
                .expect("active approval exists");
            if let Err(error) = self.client.renew_for(id, lease_id, 900_000) {
                self.active.take();
                return Err(format!("approval lease was lost: {error}"));
            }
            self.active
                .as_mut()
                .expect("approval remains active")
                .renewed_at = Instant::now();
            self.deploy_active()?;
            return Ok(None);
        }
        let active = self.active.take().ok_or("no claimed approval request")?;
        self.client
            .resolve(active.request.id, active.lease_id, false)
            .map_err(|error| error.to_string())?;
        Ok(None)
    }
}

impl Controller {
    fn save_private_key(
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
