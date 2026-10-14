//! Host-returned values this schema does not accept are never dropped: a
//! host-generated private value lost here is lost for good. They go to the
//! store's quarantine, are never deployed or treated as valid, and wait for
//! the operator to adopt or discard each one (`nix-secrets quarantine`).
use super::*;
use nix_secrets_core::{QuarantinedContent, QuarantinedValue};
use nix_secrets_transport::GeneratedRecord;

/// The deployment a returned value came from.
#[derive(Clone, Debug)]
pub(crate) struct Origin {
    pub host: String,
    pub deployment: String,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

impl Controller {
    /// Quarantines a generated record and says so, for the result.
    pub(crate) fn quarantine_record(
        &mut self,
        origin: &Origin,
        identifier: &str,
        record: &GeneratedRecord,
        reason: &str,
    ) -> String {
        let content = QuarantinedContent::GeneratedRecord {
            format_version: record.format_version,
            version_id_base64: record.version_id_base64.clone(),
            recipient_ids: record.recipient_ids.clone(),
            age_ciphertext_base64: record.age_ciphertext_base64.clone(),
            adopted: record.adopted,
        };
        self.quarantine_value(origin, identifier, reason, content, || {
            format!("its ciphertext is {}", record.age_ciphertext_base64)
        })
    }

    /// Quarantines a generated public key and says so, for the result.
    pub(crate) fn quarantine_public_key(
        &mut self,
        origin: &Origin,
        identifier: &str,
        public_key: &str,
        reason: &str,
    ) -> String {
        let content = QuarantinedContent::PublicKey {
            public_key: public_key.into(),
        };
        self.quarantine_value(origin, identifier, reason, content, || {
            format!("the key is `{public_key}`")
        })
    }

    fn quarantine_value(
        &mut self,
        origin: &Origin,
        identifier: &str,
        reason: &str,
        content: QuarantinedContent,
        fallback: impl FnOnce() -> String,
    ) -> String {
        let value = QuarantinedValue {
            identifier: identifier.into(),
            source_host: origin.host.clone(),
            deployment_id: origin.deployment.clone(),
            quarantined_at: now(),
            reason: reason.into(),
            content,
        };
        match self.client.quarantine(value) {
            Ok(id) => format!(
                "{identifier} (QUARANTINED as {id}: {reason}; adopt or discard it with `nix-secrets quarantine`)"
            ),
            // The last resort: the operator's screen and the requester's
            // result still carry the value.
            Err(error) => format!(
                "{identifier} (NOT SAVED, quarantining failed: {error}; {reason}; {})",
                fallback()
            ),
        }
    }

    /// Quarantined values of `host`, for the request.
    pub(super) fn quarantined_lines(&self, host: &str) -> Vec<String> {
        self.quarantined
            .iter()
            .filter(|(_, value)| value.source_host == host)
            .map(|(id, value)| describe(id, value))
            .collect()
    }
}

/// `id: identifier from host, deployment, time: reason`.
pub(crate) fn describe(id: &str, value: &QuarantinedValue) -> String {
    let kind = match &value.content {
        QuarantinedContent::GeneratedRecord { .. } => "generated record",
        QuarantinedContent::PublicKey { .. } => "public key",
    };
    format!(
        "{id}: {kind} {} from {} (deployment {}, at {}): {}",
        value.identifier, value.source_host, value.deployment_id, value.quarantined_at, value.reason
    )
}
