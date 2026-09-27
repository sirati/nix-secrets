#![forbid(unsafe_code)]

mod age_command;
mod age_failure;
mod error;
mod record;
mod secret;

pub use age_command::AgeCommandProvider;
pub use error::{AgeFailure, CryptoError};
pub use record::EncryptedSecret;
pub use secret::{
    CryptoProvider, MAX_CIPHERTEXT_SIZE, MAX_SECRET_SIZE, Recipient, VERSION_ID_SIZE,
    decrypt_secret, decrypt_secrets, encrypt_secret, encrypt_secret_with_version,
};

mod header;
pub use header::{
    fingerprint_stanza_tag, ssh_recipient_stanza, ssh_stanza_tags, verify_ssh_recipient_header,
};
