//! Checks an age file's recipient stanzas without decrypting it.

use base64::{
    Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::STANDARD_NO_PAD,
};
use sha2::{Digest, Sha256};

use crate::{CryptoError, MAX_CIPHERTEXT_SIZE};

const HEADER_VERSION: &str = "age-encryption.org/v1";
const MAX_HEADER_LINES: usize = 1024;

/// Verifies that `ciphertext` is an age v1 file with exactly one
/// `ssh-ed25519` or `ssh-rsa` stanza per expected recipient and no others.
///
/// age tags an SSH stanza with the first four bytes of SHA-256 over the
/// recipient's SSH public key blob. A record produced by an untrusted peer
/// could otherwise be encrypted to an extra key, or to none of the operator's
/// keys, without anyone noticing until decryption.
pub fn verify_ssh_recipient_header(
    ciphertext: &[u8],
    ssh_public_keys: &[&str],
) -> Result<(), CryptoError> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_SIZE {
        return Err(CryptoError::InvalidRecord);
    }
    let mut expected = Vec::with_capacity(ssh_public_keys.len());
    for key in ssh_public_keys {
        expected.push(stanza_tag(key)?);
    }
    expected.sort();
    let mut actual = Vec::new();
    let mut lines = ciphertext.split(|byte| *byte == b'\n');
    if lines.next() != Some(HEADER_VERSION.as_bytes()) {
        return Err(CryptoError::InvalidRecord);
    }
    for (index, line) in lines.enumerate() {
        if index > MAX_HEADER_LINES {
            return Err(CryptoError::InvalidRecord);
        }
        let line = std::str::from_utf8(line).map_err(|_| CryptoError::InvalidRecord)?;
        if line.starts_with("--- ") {
            actual.sort();
            return if actual == expected {
                Ok(())
            } else {
                Err(CryptoError::RecipientMismatch)
            };
        }
        let Some(arguments) = line.strip_prefix("-> ") else {
            continue;
        };
        let mut fields = arguments.split(' ');
        match fields.next() {
            Some(kind @ ("ssh-ed25519" | "ssh-rsa")) => {
                let tag = fields.next().ok_or(CryptoError::InvalidRecord)?;
                actual.push((kind.to_owned(), tag.to_owned()));
            }
            // Any other stanza would give some other key the file key.
            _ => return Err(CryptoError::RecipientMismatch),
        }
    }
    Err(CryptoError::InvalidRecord)
}

/// The type and tag of the age stanza that `ssh_public_key` receives.
pub fn ssh_recipient_stanza(ssh_public_key: &str) -> Result<(String, String), CryptoError> {
    stanza_tag(ssh_public_key)
}

fn stanza_tag(ssh_public_key: &str) -> Result<(String, String), CryptoError> {
    let mut fields = ssh_public_key.split_ascii_whitespace();
    let kind = fields.next().ok_or(CryptoError::InvalidRecipient)?;
    if !matches!(kind, "ssh-ed25519" | "ssh-rsa") {
        return Err(CryptoError::InvalidRecipient);
    }
    let blob = STANDARD
        .decode(fields.next().ok_or(CryptoError::InvalidRecipient)?)
        .map_err(|_| CryptoError::InvalidRecipient)?;
    let digest = Sha256::digest(&blob);
    Ok((kind.to_owned(), STANDARD_NO_PAD.encode(&digest[..4])))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
    const OTHER: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA";

    fn file(stanzas: &[String]) -> Vec<u8> {
        let mut text = String::from("age-encryption.org/v1\n");
        for stanza in stanzas {
            text.push_str(stanza);
            text.push_str("\nYWJj\n");
        }
        text.push_str("--- bWFj\n");
        let mut bytes = text.into_bytes();
        bytes.extend_from_slice(&[0, 1, 2]);
        bytes
    }

    fn stanza(key: &str) -> String {
        let (kind, tag) = stanza_tag(key).unwrap();
        format!("-> {kind} {tag} c2hhcmU")
    }

    #[test]
    fn exact_recipient_set_is_accepted() {
        assert!(verify_ssh_recipient_header(&file(&[stanza(KEY)]), &[KEY]).is_ok());
        assert!(
            verify_ssh_recipient_header(&file(&[stanza(OTHER), stanza(KEY)]), &[KEY, OTHER])
                .is_ok()
        );
    }

    #[test]
    fn missing_extra_or_foreign_recipients_are_rejected() {
        assert!(verify_ssh_recipient_header(&file(&[stanza(OTHER)]), &[KEY]).is_err());
        assert!(verify_ssh_recipient_header(&file(&[stanza(KEY), stanza(OTHER)]), &[KEY]).is_err());
        assert!(
            verify_ssh_recipient_header(&file(&[stanza(KEY), "-> X25519 c29tZQ".into()]), &[KEY])
                .is_err()
        );
        assert!(verify_ssh_recipient_header(b"not age", &[KEY]).is_err());
        assert!(verify_ssh_recipient_header(&file(&[]), &[KEY]).is_err());
    }
}

#[cfg(test)]
mod real_age {
    /// A header produced by age 1.3.2 for a known key.
    #[test]
    fn matches_age_stanza_tag() {
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMKBoj+1FHGXXmcuYPXsT5LXTdeKQAJIpwlFn7z358gG";
        assert_eq!(super::stanza_tag(key).unwrap().1, "p/a/GQ");
    }
}
