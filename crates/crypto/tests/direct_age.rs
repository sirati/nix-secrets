use nix_secrets_crypto::{
    CryptoError, CryptoProvider, EncryptedSecret, Recipient, decrypt_secret, encrypt_secret,
};
use zeroize::Zeroizing;

#[derive(Default)]
struct FakeAge;

impl CryptoProvider for FakeAge {
    fn encrypt(&self, recipients: &[&str], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        assert_eq!(recipients, ["ssh-ed25519 AAAAfirst", "ssh-rsa AAAAsecond"]);
        let mut output = b"age-encryption.org/v1\n".to_vec();
        output.extend(plaintext.iter().map(|byte| byte ^ 0x5a));
        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let body = ciphertext
            .strip_prefix(b"age-encryption.org/v1\n")
            .ok_or(CryptoError::InvalidRecord)?;
        Ok(Zeroizing::new(
            body.iter().map(|byte| byte ^ 0x5a).collect(),
        ))
    }
}

fn recipients() -> [Recipient<'static>; 2] {
    [
        Recipient {
            id: "SHA256:first",
            ssh_public_key: "ssh-ed25519 AAAAfirst",
        },
        Recipient {
            id: "SHA256:second",
            ssh_public_key: "ssh-rsa AAAAsecond",
        },
    ]
}

const MAIL_PASSWORD: &str = "host.services.mail.password";

#[test]
fn whole_secret_roundtrip_and_json_storage() {
    let plaintext = b"one whole secret\0including binary";
    let record = encrypt_secret(MAIL_PASSWORD, plaintext, &recipients(), &FakeAge).unwrap();
    assert_eq!(record.recipient_ids, ["SHA256:first", "SHA256:second"]);
    assert_eq!(record.version_id.len(), 16);
    let json = serde_json::to_string(&record).unwrap();
    assert!(!json.contains("one whole secret"));
    assert!(json.contains("age_ciphertext"));
    let decoded: EncryptedSecret = serde_json::from_str(&json).unwrap();
    assert_eq!(
        &*decrypt_secret(MAIL_PASSWORD, &decoded, &FakeAge).unwrap(),
        plaintext
    );
}

#[test]
fn same_identifier_replacements_have_new_versions_and_both_decrypt() {
    let first = encrypt_secret(MAIL_PASSWORD, b"first", &recipients(), &FakeAge).unwrap();
    let second = encrypt_secret(MAIL_PASSWORD, b"replacement", &recipients(), &FakeAge).unwrap();
    assert_ne!(first.version_id, second.version_id);
    assert_eq!(
        &*decrypt_secret(MAIL_PASSWORD, &first, &FakeAge).unwrap(),
        b"first"
    );
    assert_eq!(
        &*decrypt_secret(MAIL_PASSWORD, &second, &FakeAge).unwrap(),
        b"replacement"
    );
}

#[test]
fn cross_identifier_ciphertext_substitution_is_rejected() {
    let record = encrypt_secret(MAIL_PASSWORD, b"mail", &recipients(), &FakeAge).unwrap();
    assert!(matches!(
        decrypt_secret("host.services.git.password", &record, &FakeAge),
        Err(CryptoError::MetadataMismatch)
    ));
}

#[test]
fn outer_version_tampering_is_rejected() {
    let mut record = encrypt_secret(MAIL_PASSWORD, b"mail", &recipients(), &FakeAge).unwrap();
    record.version_id[0] ^= 1;
    assert!(matches!(
        decrypt_secret(MAIL_PASSWORD, &record, &FakeAge),
        Err(CryptoError::MetadataMismatch)
    ));
}

#[test]
fn canonical_identifier_resolves_normally() {
    let record = encrypt_secret(MAIL_PASSWORD, b"resolved", &recipients(), &FakeAge).unwrap();
    assert_eq!(
        &*decrypt_secret(MAIL_PASSWORD, &record, &FakeAge).unwrap(),
        b"resolved"
    );
}

#[test]
fn malformed_records_and_empty_recipients_are_rejected() {
    assert!(matches!(
        encrypt_secret(MAIL_PASSWORD, b"secret", &[], &FakeAge),
        Err(CryptoError::InvalidRecipient)
    ));
    assert!(matches!(
        encrypt_secret(
            "host.unknown.mail.password",
            b"secret",
            &recipients(),
            &FakeAge
        ),
        Err(CryptoError::InvalidIdentifier)
    ));
    let mut record = encrypt_secret(MAIL_PASSWORD, b"secret", &recipients(), &FakeAge).unwrap();
    record.version_id.clear();
    assert!(matches!(
        decrypt_secret(MAIL_PASSWORD, &record, &FakeAge),
        Err(CryptoError::InvalidRecord)
    ));
}
