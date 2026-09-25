use zeroize::Zeroizing;

use crate::{CryptoError, EncryptedSecret, record::FORMAT_VERSION};

const INNER_TAG: &[u8; 8] = b"NIXSECRT";
const INNER_VERSION: u8 = 1;
const VERSION_ID_SIZE: usize = 16;
const MAX_IDENTIFIER_SIZE: usize = 4096;
const INNER_FIXED_SIZE: usize = INNER_TAG.len() + 1 + 2 + VERSION_ID_SIZE;
pub const MAX_SECRET_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_PLAINTEXT_SIZE: usize = MAX_SECRET_SIZE + MAX_IDENTIFIER_SIZE + INNER_FIXED_SIZE;
pub const MAX_CIPHERTEXT_SIZE: usize = MAX_PLAINTEXT_SIZE + 1024 * 1024;

pub struct Recipient<'a> {
    /// Stable key identifier or fingerprint shown by the user interface.
    pub id: &'a str,
    pub ssh_public_key: &'a str,
}

pub trait CryptoProvider {
    fn encrypt(&self, ssh_recipients: &[&str], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

pub fn encrypt_secret(
    identifier: &str,
    plaintext: &[u8],
    recipients: &[Recipient<'_>],
    provider: &impl CryptoProvider,
) -> Result<EncryptedSecret, CryptoError> {
    validate_identifier(identifier)?;
    validate_recipients(recipients)?;
    if plaintext.len() > MAX_SECRET_SIZE {
        return Err(CryptoError::SecretTooLarge);
    }
    let mut version_id = [0_u8; VERSION_ID_SIZE];
    getrandom::fill(&mut version_id).map_err(|_| CryptoError::Randomness)?;
    let inner = encode_inner(identifier, &version_id, plaintext);
    let keys: Vec<_> = recipients
        .iter()
        .map(|entry| entry.ssh_public_key)
        .collect();
    let age_ciphertext = provider.encrypt(&keys, &inner).map_err(|error| {
        error.during(|| {
            let ids: Vec<_> = recipients.iter().map(|entry| entry.id).collect();
            format!("encrypting {identifier} for recipients {}", ids.join(", "))
        })
    })?;
    if age_ciphertext.is_empty() || age_ciphertext.len() > MAX_CIPHERTEXT_SIZE {
        return Err(CryptoError::InvalidRecord);
    }
    Ok(EncryptedSecret {
        format_version: FORMAT_VERSION,
        version_id: version_id.to_vec(),
        recipient_ids: recipients.iter().map(|entry| entry.id.to_owned()).collect(),
        age_ciphertext,
    })
}

pub fn decrypt_secret(
    identifier: &str,
    record: &EncryptedSecret,
    provider: &impl CryptoProvider,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    validate_identifier(identifier)?;
    validate_record(record)?;
    let inner = provider
        .decrypt(&record.age_ciphertext)
        .map_err(|error| error.during(|| format!("decrypting {identifier}")))?;
    decode_inner(identifier, &record.version_id, &inner)
}

fn encode_inner(
    identifier: &str,
    version_id: &[u8; VERSION_ID_SIZE],
    secret: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(
        INNER_FIXED_SIZE + identifier.len() + secret.len(),
    ));
    output.extend_from_slice(INNER_TAG);
    output.push(INNER_VERSION);
    output.extend_from_slice(&(identifier.len() as u16).to_be_bytes());
    output.extend_from_slice(identifier.as_bytes());
    output.extend_from_slice(version_id);
    output.extend_from_slice(secret);
    output
}

fn decode_inner(
    requested_identifier: &str,
    outer_version_id: &[u8],
    inner: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if inner.len() < INNER_FIXED_SIZE || &inner[..INNER_TAG.len()] != INNER_TAG {
        return Err(CryptoError::InvalidRecord);
    }
    let mut cursor = INNER_TAG.len();
    if inner[cursor] != INNER_VERSION {
        return Err(CryptoError::InvalidRecord);
    }
    cursor += 1;
    let identifier_size = u16::from_be_bytes([inner[cursor], inner[cursor + 1]]) as usize;
    cursor += 2;
    let version_start = cursor
        .checked_add(identifier_size)
        .ok_or(CryptoError::InvalidRecord)?;
    let secret_start = version_start
        .checked_add(VERSION_ID_SIZE)
        .ok_or(CryptoError::InvalidRecord)?;
    if identifier_size > MAX_IDENTIFIER_SIZE || secret_start > inner.len() {
        return Err(CryptoError::InvalidRecord);
    }
    let authenticated_identifier = std::str::from_utf8(&inner[cursor..version_start])
        .map_err(|_| CryptoError::InvalidRecord)?;
    validate_identifier(authenticated_identifier).map_err(|_| CryptoError::InvalidRecord)?;
    if authenticated_identifier != requested_identifier
        || &inner[version_start..secret_start] != outer_version_id
    {
        return Err(CryptoError::MetadataMismatch);
    }
    let secret = &inner[secret_start..];
    if secret.len() > MAX_SECRET_SIZE {
        return Err(CryptoError::SecretTooLarge);
    }
    Ok(Zeroizing::new(secret.to_vec()))
}

fn validate_identifier(identifier: &str) -> Result<(), CryptoError> {
    let components: Vec<_> = identifier.split('.').collect();
    let namespace = components.get(1).copied().unwrap_or_default();
    let valid_namespace = namespace == "services"
        || (namespace.starts_with("user-") && namespace.ends_with("-services"));
    let valid = identifier.len() <= MAX_IDENTIFIER_SIZE
        && components.len() >= 4
        && valid_namespace
        && components.iter().all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    if valid {
        Ok(())
    } else {
        Err(CryptoError::InvalidIdentifier)
    }
}

fn validate_recipients(recipients: &[Recipient<'_>]) -> Result<(), CryptoError> {
    if recipients.is_empty()
        || recipients.iter().any(|entry| {
            entry.id.is_empty()
                || entry.id.chars().any(char::is_control)
                || entry.ssh_public_key.is_empty()
        })
    {
        return Err(CryptoError::InvalidRecipient);
    }
    Ok(())
}

fn validate_record(record: &EncryptedSecret) -> Result<(), CryptoError> {
    if record.format_version != FORMAT_VERSION
        || record.version_id.len() != VERSION_ID_SIZE
        || record.recipient_ids.is_empty()
        || record.recipient_ids.iter().any(String::is_empty)
        || record.age_ciphertext.is_empty()
        || record.age_ciphertext.len() > MAX_CIPHERTEXT_SIZE
    {
        return Err(CryptoError::InvalidRecord);
    }
    Ok(())
}
