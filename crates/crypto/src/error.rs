use thiserror::Error;

pub use crate::age_failure::AgeFailure;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("secret identifier is not canonical")]
    InvalidIdentifier,
    #[error("invalid SSH recipient")]
    InvalidRecipient,
    #[error("encrypted secret record is invalid")]
    InvalidRecord,
    #[error("authenticated secret metadata does not match the requested record")]
    MetadataMismatch,
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("could not execute age: {0}")]
    AgeIo(#[from] std::io::Error),
    #[error("{0}")]
    AgeFailed(Box<AgeFailure>),
    #[error("age produced an unexpectedly large result")]
    AgeOutputTooLarge,
    #[error("secret exceeds the configured size limit")]
    SecretTooLarge,
    #[error("age input worker terminated unexpectedly")]
    InputWorkerFailed,
}

impl CryptoError {
    /// Names the operation of a failed age run, for example which secret was
    /// being decrypted.
    pub(crate) fn during(mut self, operation: impl FnOnce() -> String) -> Self {
        if let Self::AgeFailed(failure) = &mut self {
            failure.operation.get_or_insert_with(operation);
        }
        self
    }
}
