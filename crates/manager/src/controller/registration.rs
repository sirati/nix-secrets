use super::*;
use std::collections::BTreeMap;

impl Controller {
    pub(super) fn register_public_keys(
        &mut self,
        source_host: &str,
        keys: &BTreeMap<String, String>,
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
            let Some(destination_id) = generated.generated_secret.register_at else {
                continue;
            };
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
            let (stamp, public_key) = parse_dated_key(dated_key)?;
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
                let lines = if let Some(stored) = current {
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
                match self.client.set_if_version(
                    &destination,
                    updated.as_bytes(),
                    &recipients,
                    &self.provider,
                    current.map(|record| record.version_id.clone()),
                ) {
                    Ok(()) => {
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
    if fields.next().is_some()
        || stamp.len() != 19
        || !stamp.bytes().all(|b| b.is_ascii_alphanumeric())
        || algorithm != "ssh-ed25519"
        || material.len() != 68
        || !material
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
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
    fn replaces_only_same_hosts_key() {
        let current =
            "other-20260922T120000Z ssh-ed25519 AAAA\nnode-20260922T120000Z ssh-ed25519 BBBB\n";
        let updated = merge_named_key(current, "node", "node-20260923T120000Z", "ssh-ed25519 CCCC");
        assert!(updated.contains("other-20260922T120000Z"));
        assert!(!updated.contains("node-20260922T120000Z"));
        assert!(updated.contains("node-20260923T120000Z ssh-ed25519 CCCC"));
    }
}
