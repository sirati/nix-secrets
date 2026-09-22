use super::*;

impl SecretWriter for Controller {
    fn generate(&mut self, path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let path = SecretPath::parse(path).map_err(|error| error.to_string())?;
        let leaf = self.schema.leaf(&path).map_err(|error| error.to_string())?;
        let policy = match leaf {
            LeafSpec::Stored(spec) => spec.generation,
            LeafSpec::Generated(spec) => spec.generation,
        }
        .ok_or_else(|| format!("generation is not authorized for {path}"))?;
        crate::generator::generate(&manager_policy(policy)).map_err(|error| error.to_string())
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
        match self
            .client
            .set(&parsed, &value, &recipients, &self.provider)
        {
            Ok(()) => Ok(Action::Saved(parsed.to_string())),
            Err(error) => Err((error.to_string(), value)),
        }
    }

    fn poll_approval(&mut self) -> Result<Option<UiApproval>, String> {
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

    fn request_deployment(&mut self, path: &str) -> Result<(), String> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = SecretPath::parse(path).map_err(|error| error.to_string())?;
        let target = path
            .components()
            .first()
            .cloned()
            .ok_or("secret has no target")?;
        let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let id = format!("manager-{}-{nonce}", std::process::id());
        self.client
            .submit_approval(ApprovalRequest {
                id,
                target,
                secrets: vec![path.to_string()],
            })
            .map_err(|error| error.to_string())
    }
}

fn manager_policy(
    policy: nix_secrets_core::GenerationPolicy,
) -> crate::generator::GenerationPolicy {
    use nix_secrets_core::{ByteEncoding, PassphraseSeparator, PasswordAlphabet};
    match policy {
        nix_secrets_core::GenerationPolicy::RandomPassword { length, alphabet } => {
            let alphabet = match alphabet {
                PasswordAlphabet::Alphanumeric => {
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                }
                PasswordAlphabet::AsciiSafe => concat!(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    "!#$%&()*+,-./:;<=>?@[]^_{|}~"
                ),
            };
            crate::generator::GenerationPolicy::Password {
                length: usize::from(length),
                alphabet: alphabet.into(),
            }
        }
        nix_secrets_core::GenerationPolicy::RandomPassphrase {
            words, separator, ..
        } => crate::generator::GenerationPolicy::Passphrase {
            words: usize::from(words),
            separator: match separator {
                PassphraseSeparator::Hyphen => "-",
                PassphraseSeparator::Underscore => "_",
                PassphraseSeparator::Space => " ",
            }
            .into(),
            word_list: crate::generator::eff_large_words(),
        },
        nix_secrets_core::GenerationPolicy::RandomBytes { bytes, encoding } => {
            crate::generator::GenerationPolicy::Bytes {
                length: usize::from(bytes),
                encoding: match encoding {
                    ByteEncoding::Base64urlUnpadded => {
                        crate::generator::ByteEncoding::Base64UrlUnpadded
                    }
                    ByteEncoding::Base64 => crate::generator::ByteEncoding::Base64,
                    ByteEncoding::Hex => crate::generator::ByteEncoding::HexLower,
                },
            }
        }
    }
}
