//! Batches of stored values for another program: validated against the
//! schema and store, described for the approval modal, and decrypted with
//! one provider call (one 1Password authorization).
use crate::client::BackendClient;
use nix_secrets_core::{EncryptedSecret as StoredSecret, LeafSpec, Schema, SecretKind, SecretPath};
use nix_secrets_crypto::{decrypt_secrets, CryptoProvider, EncryptedSecret};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Decrypted values by identifier; each is erased when dropped.
pub type Values = BTreeMap<String, Zeroizing<Vec<u8>>>;

/// One requested value as the operator sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestedValue {
    pub identifier: String,
    /// `secret`, `operator key` or `task input`.
    pub kind: String,
    pub description: Option<String>,
    /// Recipients the value is encrypted to: name or id, and the SSH key
    /// fingerprint. The provider decrypts with whichever of them it holds.
    pub recipients: Vec<String>,
}

/// Validated values with their stored ciphertexts.
pub struct Batch {
    pub values: Vec<RequestedValue>,
    records: Vec<(String, StoredSecret)>,
}

/// Checks every identifier: declared, not public information, and set.
/// Reads the ciphertexts now, so what is shown is what is decrypted.
pub fn load(
    client: &mut BackendClient,
    schema: &Schema,
    identifiers: &[String],
) -> Result<Batch, String> {
    load_with_policy(client, schema, identifiers, false)
}

/// Used only by the frontend's detached-signature handler. The returned
/// plaintext remains on the frontend and is never a SecretAnswer::Approved.
pub(crate) fn load_for_signing(client: &mut BackendClient, schema: &Schema, identifiers: &[String]) -> Result<Batch, String> {
    load_with_policy(client, schema, identifiers, true)
}

fn load_with_policy(client: &mut BackendClient, schema: &Schema, identifiers: &[String], signing: bool) -> Result<Batch, String> {
    let mut values = Vec::new();
    let mut records = Vec::new();
    // The agent names each key by its title; listing asks nothing.
    let agent = crate::key_names::AgentKeys::from_agent(None);
    for identifier in identifiers {
        let path =
            SecretPath::parse(identifier).map_err(|error| format!("{identifier}: {error}"))?;
        let leaf = schema
            .leaf(&path)
            .map_err(|error| format!("{identifier}: {error}"))?;
        let (kind, description) = match &leaf {
            LeafSpec::Operator(spec) if spec.signing_only && !signing => return Err(format!("{identifier} is signing-only; plaintext export is forbidden")),
            LeafSpec::Stored(spec) if matches!(spec.kind, SecretKind::PublicInfo) => {
                return Err(format!("{identifier} is public information, not a secret"))
            }
            LeafSpec::Stored(spec) => ("secret", spec.description.clone()),
            LeafSpec::Operator(spec) => ("operator key", spec.description.clone()),
            LeafSpec::Generated(spec) => ("task input", spec.description.clone()),
        };
        let record = client
            .get(&path)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("{identifier} is unset"))?;
        let (ids, keys) = leaf.recipients();
        let names = leaf.recipient_names();
        let recipients = ids
            .iter()
            .zip(keys)
            .enumerate()
            .map(|(index, (id, key))| {
                let name = names
                    .get(index)
                    .cloned()
                    .or_else(|| crate::key_names::schema_name(schema, key))
                    .unwrap_or_else(|| id.chars().take(12).collect());
                let name = format!("{name} {}", crate::key_names::agent_title(&agent, key));
                match ssh_key::PublicKey::from_openssh(key) {
                    Ok(key) => format!(
                        "{name}: {} {}",
                        key.algorithm(),
                        key.fingerprint(ssh_key::HashAlg::Sha256)
                    ),
                    Err(_) => format!("{name}: {key}"),
                }
            })
            .collect();
        values.push(RequestedValue {
            identifier: identifier.clone(),
            kind: kind.into(),
            description,
            recipients,
        });
        records.push((identifier.clone(), record));
    }
    Ok(Batch { values, records })
}

impl Batch {
    /// Decrypts every value with one provider batch.
    pub fn decrypt(&self, provider: &impl CryptoProvider) -> Result<Values, String> {
        let envelopes = self
            .records
            .iter()
            .map(|(identifier, record)| {
                (
                    identifier.as_str(),
                    EncryptedSecret {
                        format_version: record.format_version,
                        version_id: record.version_id.clone(),
                        recipient_ids: record.recipient_ids.clone(),
                        age_ciphertext: record.age_ciphertext.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();
        let borrowed = envelopes
            .iter()
            .map(|(identifier, envelope)| (*identifier, envelope))
            .collect::<Vec<_>>();
        let plaintexts = decrypt_secrets(&borrowed, provider).map_err(|error| error.to_string())?;
        Ok(self
            .records
            .iter()
            .map(|(identifier, _)| identifier.clone())
            .zip(plaintexts)
            .collect())
    }
}
