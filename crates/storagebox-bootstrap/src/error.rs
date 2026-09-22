#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid storage-box bootstrap task: {0}")]
    InvalidTask(String),
    #[error("authorized_keys is invalid: {0}")]
    InvalidAuthorizedKeys(String),
    #[error("stored private key is invalid")]
    InvalidPrivateKey,
    #[error("SSH operation failed: {0}")]
    Ssh(String),
    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("key generation failed")]
    KeyGeneration,
}
