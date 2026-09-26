use super::*;

pub(super) fn hydrate_record(
    document: &StoreDocument,
    record: &EncryptedSecret,
) -> Result<EncryptedSecret, StoreError> {
    let mut value = record.clone();
    if !value.recipient_refs.is_empty() {
        if !value.recipient_ids.is_empty() {
            return Err(StoreError::InvalidRecipientRegistry);
        }
        value.recipient_ids = value
            .recipient_refs
            .iter()
            .map(|reference| {
                document
                    .recipient_registry
                    .get(reference)
                    .cloned()
                    .ok_or(StoreError::InvalidRecipientRegistry)
            })
            .collect::<Result<Vec<_>, _>>()?;
    }
    Ok(value)
}

pub(super) fn validate_public_metadata(
    leaf: &LeafSpec,
    public_key: Option<&str>,
) -> Result<(), StoreError> {
    let private_key = match leaf {
        LeafSpec::Stored(spec) => {
            if spec.destination.content_type.as_deref() == Some("openssh-private-key") {
                if public_key.is_none() {
                    return Err(StoreError::InvalidPublicKey);
                }
                true
            } else {
                false
            }
        }
        LeafSpec::Generated(spec) => {
            spec.generated_secret.output.content_type.as_deref() == Some("openssh-private-key")
        }
        LeafSpec::Operator(spec) => {
            // The generated public half, base64 of the generator's fd 3 bytes.
            return match public_key {
                None => Ok(()),
                Some(key) if spec.generator.is_some() && valid_operator_public_key(key) => Ok(()),
                Some(_) => Err(StoreError::InvalidPublicKey),
            };
        }
    };
    if public_key
        .is_some_and(|key| !private_key || !crate::schema::validation::valid_ssh_public_key(key))
    {
        return Err(StoreError::InvalidPublicKey);
    }
    Ok(())
}

/// Largest public key an operator generator may return (ML-DSA-87 is 2592).
pub const MAX_OPERATOR_PUBLIC_KEY_BYTES: usize = 64 * 1024;

fn valid_operator_public_key(key: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(key)
        .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_OPERATOR_PUBLIC_KEY_BYTES)
}

pub(super) fn validate_record(record: &EncryptedSecret) -> Result<(), StoreError> {
    const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024 * 1024;
    if record.format_version != 1
        || record.version_id.len() != 16
        || record.recipient_ids.is_empty()
        || record.age_ciphertext.is_empty()
        || record.age_ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(StoreError::InvalidRecord);
    }
    Ok(())
}
