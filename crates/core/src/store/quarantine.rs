//! Values a host returned that this schema does not accept: a generated
//! record nobody requested or whose recipients differ, a record that lost a
//! race with an operator's write, a public key outside the approved tasks.
//! A host-generated private value lost here is lost for good, so each one is
//! kept in the `quarantine` table, with where it came from and why. Nothing
//! reads that table for deployment; the operator adopts or discards each
//! entry explicitly.
use super::*;

/// One quarantined value. Never deployed and never treated as valid.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantinedValue {
    /// The identifier the host returned it under.
    pub identifier: String,
    pub source_host: String,
    /// The approval request of the deployment that returned it.
    pub deployment_id: String,
    /// Seconds since the Unix epoch.
    pub quarantined_at: u64,
    pub reason: String,
    pub content: QuarantinedContent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum QuarantinedContent {
    /// A target-generated value, as the host encrypted it.
    GeneratedRecord {
        format_version: u16,
        version_id_base64: String,
        recipient_ids: Vec<String>,
        age_ciphertext_base64: String,
        adopted: bool,
    },
    /// The public half of a key the host generated.
    PublicKey { public_key: String },
}

const MAX_QUARANTINE: usize = 1024;
const MAX_TEXT: usize = 4096;
const MAX_CONTENT: usize = 32 * 1024 * 1024;

impl QuarantinedValue {
    fn validate(&self) -> Result<(), StoreError> {
        let content_len = match &self.content {
            QuarantinedContent::GeneratedRecord {
                version_id_base64,
                recipient_ids,
                age_ciphertext_base64,
                ..
            } => version_id_base64.len()
                + age_ciphertext_base64.len()
                + recipient_ids.iter().map(String::len).sum::<usize>(),
            QuarantinedContent::PublicKey { public_key } => public_key.len(),
        };
        let texts = [
            &self.identifier,
            &self.source_host,
            &self.deployment_id,
            &self.reason,
        ];
        if texts.iter().any(|text| text.len() > MAX_TEXT)
            || self.identifier.is_empty()
            || self.source_host.is_empty()
            || content_len > MAX_CONTENT
        {
            return Err(StoreError::InvalidQuarantine);
        }
        Ok(())
    }
}

impl SecretStore {
    /// Keeps `value` and returns its quarantine id.
    pub fn quarantine(&self, value: QuarantinedValue) -> Result<String, StoreError> {
        value.validate()?;
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|error| StoreError::Io(io::Error::other(error.to_string())))?;
        let id = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        self.with_lock(true, |document| {
            if document.quarantine.len() >= MAX_QUARANTINE {
                return Err(StoreError::InvalidQuarantine);
            }
            document.quarantine.insert(id.clone(), value);
            Ok(())
        })?;
        Ok(id)
    }

    pub fn list_quarantine(&self) -> Result<BTreeMap<String, QuarantinedValue>, StoreError> {
        self.with_lock(false, |document| Ok(document.quarantine.clone()))
    }

    /// Removes one entry, after the operator adopted or discarded it.
    pub fn remove_quarantined(&self, id: &str) -> Result<bool, StoreError> {
        self.with_lock(true, |document| Ok(document.quarantine.remove(id).is_some()))
    }
}
