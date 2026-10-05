use super::host_mutations::{HostMutation, HostMutationBatch, named_key_fingerprints};
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::BTreeMap;

impl Controller {
    /// Stage host-returned keys; no nonempty stored value is modified here.
    pub(super) fn stage_public_keys(
        &mut self,
        source_host: &str,
        keys: &BTreeMap<String, String>,
        prefetched: &BTreeMap<String, (Vec<u8>, Zeroizing<Vec<u8>>)>,
        batch: &mut HostMutationBatch,
    ) -> Result<(), String> {
        if source_host.is_empty()
            || !source_host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("invalid source hostname for public key registration".into());
        }
        // Group all returned keys for one destination before encryption/CAS.
        let mut proposed = BTreeMap::<String, Vec<(String, String)>>::new();
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
                    (None, dated_key.as_str())
                }
            };
            self.stage_generated_public_key(
                &source,
                generated.generated_secret.secret_type,
                public_key,
                batch,
            )?;
            if let Some(destination) = generated.generated_secret.register_at {
                let stamp = stamp.ok_or("Storage Box task cannot register an authorized key")?;
                proposed
                    .entry(destination)
                    .or_default()
                    .push((format!("{source_host}-{stamp}"), public_key.into()));
            }
        }
        for (identifier, additions) in proposed {
            let path = SecretPath::parse(&identifier).map_err(|e| e.to_string())?;
            let LeafSpec::Stored(target) = self.schema.leaf(&path).map_err(|e| e.to_string())?
            else {
                return Err("public key registration destination must be a stored secret".into());
            };
            if target.destination.content_type.as_deref() != Some("named-ssh-ed25519-public-keys") {
                return Err(
                    "public key registration destination lacks named-key validation".into(),
                );
            }
            let current = self.client.get(&path).map_err(|e| e.to_string())?;
            let lines = if let Some(stored) = &current {
                if let Some((_, value)) = prefetched
                    .get(&identifier)
                    .filter(|(version, _)| *version == stored.version_id)
                {
                    String::from_utf8(value.to_vec())
                        .map_err(|_| "registered public keys are not UTF-8")?
                } else {
                    let envelope = EncryptedSecret {
                        format_version: stored.format_version,
                        version_id: stored.version_id.clone(),
                        recipient_ids: stored.recipient_ids.clone(),
                        age_ciphertext: stored.age_ciphertext.clone(),
                    };
                    String::from_utf8(
                        decrypt_secret(&identifier, &envelope, &self.provider)
                            .map_err(|e| e.to_string())?
                            .to_vec(),
                    )
                    .map_err(|_| "registered public keys are not UTF-8")?
                }
            } else {
                String::new()
            };
            let mut updated = lines.clone();
            for (name, key) in additions {
                updated = merge_named_key(&updated, source_host, &name, &key);
            }
            if updated == lines {
                continue;
            }
            let recipients = target
                .recipient_ids
                .iter()
                .zip(&target.recipient_public_keys)
                .map(|(id, key)| Recipient {
                    id,
                    ssh_public_key: key,
                })
                .collect::<Vec<_>>();
            let encrypted = nix_secrets_crypto::encrypt_secret(
                &identifier,
                updated.as_bytes(),
                &recipients,
                &self.provider,
            )
            .map_err(|e| e.to_string())?;
            let envelope = nix_secrets_core::EncryptedSecret {
                format_version: encrypted.format_version,
                version_id: encrypted.version_id,
                recipient_ids: encrypted.recipient_ids,
                recipient_refs: vec![],
                age_ciphertext: encrypted.age_ciphertext,
                public_key: None,
            };
            batch.mutations.push(HostMutation::Inventory {
                path: path.clone(),
                previous_version: current.map(|old| old.version_id),
                previous_keys: named_key_fingerprints(&lines),
                proposed: envelope,
                proposed_keys: named_key_fingerprints(&updated),
            });
            batch.followup(&path)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn register_public_keys(
        &mut self,
        source: &str,
        keys: &BTreeMap<String, String>,
        prefetched: &BTreeMap<String, (Vec<u8>, Zeroizing<Vec<u8>>)>,
    ) -> Result<(), String> {
        let mut batch = HostMutationBatch::default();
        self.stage_public_keys(source, keys, prefetched, &mut batch)?;
        self.apply_host_mutations(batch)
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
    let host_lines = lines
        .lines()
        .filter(|line| owns_named_line(line, host))
        .collect::<Vec<_>>();
    if let [existing] = host_lines.as_slice() {
        let existing_key = existing
            .split_once(char::is_whitespace)
            .map(|(_, key)| key.trim());
        if let (Some(Ok(existing)), Ok(incoming)) = (
            existing_key.map(ssh_key::PublicKey::from_openssh),
            ssh_key::PublicKey::from_openssh(public_key),
        ) {
            if existing.key_data() == incoming.key_data() {
                return lines.to_owned();
            }
        }
    }
    let mut updated = lines
        .lines()
        .filter(|line| !owns_named_line(line, host))
        .collect::<Vec<_>>()
        .join("\n");
    if !updated.is_empty() {
        updated.push('\n');
    }
    updated.push_str(&format!("{name} {public_key}\n"));
    updated
}

fn owns_named_line(line: &str, host: &str) -> bool {
    line.split_ascii_whitespace()
        .next()
        .and_then(|name| name.rsplit_once('-'))
        .is_some_and(|(owner, _)| owner == host)
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod integration_tests;

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
