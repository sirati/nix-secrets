use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeMap;

impl Controller {
    /// Registers the target's new public keys. `prefetched` holds inventory
    /// values decrypted in the deployment's batch, by identifier, with the
    /// version they were read at; they are used while still current, so a
    /// registration needs no further 1Password authorization.
    pub(super) fn register_public_keys(
        &mut self,
        source_host: &str,
        keys: &BTreeMap<String, String>,
        prefetched: &BTreeMap<String, (Vec<u8>, Zeroizing<Vec<u8>>)>,
    ) -> Result<(), String> {
        if source_host.is_empty()
            || !source_host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("invalid source hostname for public key registration".into());
        }
        for (identifier, dated_key) in keys {
            let source = SecretPath::parse(identifier).map_err(|e| e.to_string())?;
            if source.components().first().map(String::as_str) != Some(source_host) {
                return Err("generated key belongs to another host".into());
            }
            let LeafSpec::Generated(generated) =
                self.schema.leaf(&source).map_err(|e| e.to_string())?
            else {
                return Err("generated key response did not match the schema".into());
            };
            let (stamp, public_key) = match generated.generated_secret.secret_type {
                nix_secrets_core::GeneratedSecretType::LocalSshKey => {
                    let (stamp, key) = parse_dated_key(dated_key)?;
                    (Some(stamp), key)
                }
                nix_secrets_core::GeneratedSecretType::StorageBoxSshKey => {
                    let key = ssh_key::PublicKey::from_openssh(dated_key)
                        .map_err(|_| "invalid target Storage Box public key")?;
                    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
                        return Err("target Storage Box key is not Ed25519".into());
                    }
                    (None, dated_key.as_str())
                }
            };
            self.save_generated_public_key(
                &source,
                generated.generated_secret.secret_type,
                public_key,
            )?;
            let Some(destination_id) = generated.generated_secret.register_at else {
                continue;
            };
            let stamp = stamp.ok_or("Storage Box task cannot register an authorized key")?;
            let destination = SecretPath::parse(&destination_id).map_err(|e| e.to_string())?;
            let LeafSpec::Stored(target) =
                self.schema.leaf(&destination).map_err(|e| e.to_string())?
            else {
                return Err("public key registration destination must be a stored secret".into());
            };
            if target.destination.content_type.as_deref() != Some("named-ssh-ed25519-public-keys") {
                return Err(
                    "public key registration destination lacks named-key validation".into(),
                );
            }
            let name = format!("{source_host}-{stamp}");
            let recipients = target
                .recipient_ids
                .iter()
                .zip(&target.recipient_public_keys)
                .map(|(id, key)| Recipient {
                    id,
                    ssh_public_key: key,
                })
                .collect::<Vec<_>>();
            let mut registered = false;
            for _ in 0..3 {
                let previous = self.client.list().map_err(|e| e.to_string())?;
                let current = previous.get(&destination_id);
                let cached = current.and_then(|stored| {
                    prefetched
                        .get(&destination_id)
                        .filter(|(version, _)| *version == stored.version_id)
                        .map(|(_, value)| value.to_vec())
                });
                let lines = if let Some(value) = cached {
                    String::from_utf8(value).map_err(|_| "registered public keys are not UTF-8")?
                } else if let Some(stored) = current {
                    let envelope = EncryptedSecret {
                        format_version: stored.format_version,
                        version_id: stored.version_id.clone(),
                        recipient_ids: stored.recipient_ids.clone(),
                        age_ciphertext: stored.age_ciphertext.clone(),
                    };
                    String::from_utf8(
                        decrypt_secret(&destination_id, &envelope, &self.provider)
                            .map_err(|e| e.to_string())?
                            .to_vec(),
                    )
                    .map_err(|_| "registered public keys are not UTF-8")?
                } else {
                    String::new()
                };
                let updated = merge_named_key(&lines, source_host, &name, public_key);
                // Encrypted here, so the read-back compares the stored record
                // with this exact ciphertext instead of decrypting it again.
                let encrypted = nix_secrets_crypto::encrypt_secret(
                    &destination_id,
                    updated.as_bytes(),
                    &recipients,
                    &self.provider,
                )
                .map_err(|e| e.to_string())?;
                let envelope = nix_secrets_core::EncryptedSecret {
                    format_version: encrypted.format_version,
                    version_id: encrypted.version_id.clone(),
                    recipient_ids: encrypted.recipient_ids.clone(),
                    recipient_refs: vec![],
                    age_ciphertext: encrypted.age_ciphertext.clone(),
                    public_key: None,
                };
                match self.client.set_envelope_if_version(
                    &destination,
                    envelope,
                    current.map(|record| record.version_id.clone()),
                ) {
                    Ok(()) => {
                        let saved = self
                            .client
                            .get(&destination)
                            .map_err(|e| e.to_string())?
                            .ok_or("registered public key disappeared after save")?;
                        if saved.version_id != encrypted.version_id
                            || saved.age_ciphertext != encrypted.age_ciphertext
                        {
                            return Err(
                                "registered public key failed read-back verification".into()
                            );
                        }
                        registered = true;
                        break;
                    }
                    Err(error)
                        if error
                            .to_string()
                            .contains("secret version changed during update") =>
                    {
                        continue
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            if !registered {
                return Err("public key inventory changed repeatedly; retry registration".into());
            }
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|_| "cannot create key registration request ID")?;
            let id = format!(
                "pubkey-{}",
                random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let target_host = destination
                .components()
                .first()
                .cloned()
                .ok_or("registration has no target")?;
            self.client
                .submit_approval(ApprovalRequest {
                    id,
                    target: target_host,
                    secrets: vec![destination_id],
                    allow_partial: false,
                })
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

fn parse_dated_key(value: &str) -> Result<(&str, &str), String> {
    let mut fields = value.split_ascii_whitespace();
    let stamp = fields.next().ok_or("missing target key timestamp")?;
    let algorithm = fields.next().ok_or("missing public key algorithm")?;
    let material = fields.next().ok_or("missing public key material")?;
    let valid_stamp = stamp.len() == 19
        && stamp.bytes().enumerate().all(|(index, byte)| {
            if index == 8 {
                byte == b'T'
            } else if index == 18 {
                byte == b'Z'
            } else {
                byte.is_ascii_digit()
            }
        });
    let valid_blob = STANDARD.decode(material).ok().is_some_and(|blob| {
        blob.len() == 51
            && &blob[..15] == b"\0\0\0\x0bssh-ed25519"
            && &blob[15..19] == b"\0\0\0\x20"
    });
    if fields.next().is_some()
        || !valid_stamp
        || algorithm != "ssh-ed25519"
        || material.len() != 68
        || !valid_blob
    {
        return Err("invalid target generated public key".into());
    }
    Ok((stamp, value.trim_start_matches(stamp).trim()))
}

fn merge_named_key(lines: &str, host: &str, name: &str, public_key: &str) -> String {
    let mut updated = lines
        .lines()
        .filter(|line| !line.starts_with(&format!("{host}-")))
        .collect::<Vec<_>>()
        .join("\n");
    if !updated.is_empty() {
        updated.push('\n');
    }
    updated.push_str(&format!("{name} {public_key}\n"));
    updated
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_target_timestamp_and_ed25519_blob() {
        let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        blob.extend_from_slice(&[7; 32]);
        let key = format!("20260923T120001123Z ssh-ed25519 {}", STANDARD.encode(blob));
        assert!(parse_dated_key(&key).is_ok());
        assert!(parse_dated_key(&key.replace("20260923T", "20260923X")).is_err());
        assert!(parse_dated_key("20260923T120001123Z ssh-ed25519 AAAA").is_err());
    }
    #[test]
    fn replaces_only_same_hosts_key() {
        let current =
            "other-20260922T120000Z ssh-ed25519 AAAA\nnode-20260922T120000Z ssh-ed25519 BBBB\n";
        let updated = merge_named_key(current, "node", "node-20260923T120000Z", "ssh-ed25519 CCCC");
        assert!(updated.contains("other-20260922T120000Z"));
        assert!(!updated.contains("node-20260922T120000Z"));
        assert!(updated.contains("node-20260923T120000Z ssh-ed25519 CCCC"));
    }
}
