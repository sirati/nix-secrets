use thiserror::Error;

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
    #[error("age exited unsuccessfully with status {0:?}")]
    AgeFailed(Option<i32>),
    #[error("age produced an unexpectedly large result")]
    AgeOutputTooLarge,
    #[error("secret exceeds the configured size limit")]
    SecretTooLarge,
    #[error("age input worker terminated unexpectedly")]
    InputWorkerFailed,
}
