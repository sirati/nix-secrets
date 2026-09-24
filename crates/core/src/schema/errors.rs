use super::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("secret path must have at least four components")]
    TooShort,
    #[error("invalid path component {0:?}")]
    InvalidComponent(String),
    #[error("invalid service namespace {0:?}")]
    InvalidNamespace(String),
    #[error("schema path does not exist: {0}")]
    NotFound(SecretPath),
    #[error("schema path is a branch: {0}")]
    IsBranch(SecretPath),
    #[error("schema path has the wrong leaf kind: {0}")]
    WrongKind(SecretPath),
    #[error("secret has no recipient public key: {0}")]
    MissingPublicKey(SecretPath),
    #[error("recipient key and identifier counts differ: {0}")]
    RecipientCount(SecretPath),
    #[error("invalid destination for {0}: {1}")]
    InvalidDestination(SecretPath, String),
    #[error("invalid value definition for {0}: {1}")]
    InvalidValueDefinition(SecretPath, String),
}

#[derive(Debug, Error)]
pub enum SchemaLoadError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Schema(#[from] SchemaError),
}
