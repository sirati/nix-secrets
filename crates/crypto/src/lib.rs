#![forbid(unsafe_code)]

mod age_command;
mod age_failure;
mod error;
mod record;
mod secret;

pub use age_command::AgeCommandProvider;
pub use error::{AgeFailure, CryptoError};
pub use record::EncryptedSecret;
pub use secret::{CryptoProvider, Recipient, decrypt_secret, encrypt_secret};
