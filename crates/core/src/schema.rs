use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;

mod generated;
mod generation;
mod validation;
pub use generated::{
    GeneratedKind, GeneratedSecret, GeneratedSecretLeaf, GeneratedSecretType, StorageBoxBootstrap,
};
pub use generation::{
    ByteEncoding, GenerationPolicy, PassphraseSeparator, PassphraseWordList, PasswordAlphabet,
};
use validation::{validate_component, validate_namespace, validate_tree};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Schema(pub BTreeMap<String, HostSchema>);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMetadata {
    #[serde(rename = "socketPath")]
    pub socket_path: String,
    pub deployment: DeploymentMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentMetadata {
    pub host: String,
    pub destination: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostSchema {
    pub metadata: HostMetadata,
    #[serde(flatten)]
    pub service_groups: BTreeMap<String, BTreeMap<String, SecretNode>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SecretNode {
    Generated(GeneratedSecretLeaf),
    Secret(SecretLeaf),
    Branch(BTreeMap<String, SecretNode>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretLeaf {
    pub kind: SecretKind,
    #[serde(rename = "recipientPublicKeys")]
    pub recipient_public_keys: Vec<String>,
    #[serde(rename = "recipientIds")]
    pub recipient_ids: Vec<String>,
    pub destination: Destination,
    #[serde(rename = "consumerUnits")]
    pub consumer_units: Vec<String>,
    pub generation: Option<GenerationPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SecretKind {
    #[serde(rename = "secret")]
    Secret,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub path: String,
    pub category: String,
    pub owner: String,
    pub group: String,
    pub mode: String,
    #[serde(rename = "contentType", default)]
    pub content_type: Option<String>,
    #[serde(rename = "authorizedForUser", default)]
    pub authorized_for_user: Option<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SecretPath(Vec<String>);

#[derive(Clone, Debug)]
pub struct SecretSpec {
    pub path: SecretPath,
    pub recipient_public_keys: Vec<String>,
    pub recipient_ids: Vec<String>,
    pub destination: Destination,
    pub consumer_units: Vec<String>,
    pub generation: Option<GenerationPolicy>,
}

#[derive(Clone, Debug)]
pub struct GeneratedSecretSpec {
    pub path: SecretPath,
    pub recipient_public_keys: Vec<String>,
    pub recipient_ids: Vec<String>,
    pub generated_secret: GeneratedSecret,
    pub consumer_units: Vec<String>,
    pub generation: Option<GenerationPolicy>,
}

#[derive(Clone, Debug)]
pub enum LeafSpec {
    Stored(SecretSpec),
    Generated(GeneratedSecretSpec),
}

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
    #[error("invalid generation policy for {0}")]
    InvalidGeneration(SecretPath),
}

#[derive(Debug, Error)]
pub enum SchemaLoadError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Schema(#[from] SchemaError),
}

impl SecretPath {
    pub fn new(parts: impl IntoIterator<Item = String>) -> Result<Self, SchemaError> {
        let parts: Vec<_> = parts.into_iter().collect();
        if parts.len() < 4 {
            return Err(SchemaError::TooShort);
        }
        for part in &parts {
            validate_component(part)?;
        }
        validate_namespace(&parts[1])?;
        Ok(Self(parts))
    }

    pub fn parse(path: &str) -> Result<Self, SchemaError> {
        Self::new(path.split('.').map(str::to_owned))
    }

    pub fn components(&self) -> &[String] {
        &self.0
    }
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.join("."))
    }
}

impl Schema {
    pub fn from_json(input: &str) -> Result<Self, SchemaLoadError> {
        let schema: Self = serde_json::from_str(input)?;
        schema.validate()?;
        Ok(schema)
    }

    pub fn validate(&self) -> Result<(), SchemaError> {
        for (host_name, host) in &self.0 {
            validate_component(host_name)?;
            if !host.metadata.socket_path.starts_with('/') {
                return Err(SchemaError::InvalidDestination(
                    synthetic_path(host_name),
                    "socketPath must be absolute".into(),
                ));
            }
            if host.metadata.deployment.host.is_empty()
                || host.metadata.deployment.destination.is_empty()
                || host.metadata.deployment.port == 0
            {
                return Err(SchemaError::InvalidDestination(
                    synthetic_path(host_name),
                    "deployment metadata is incomplete".into(),
                ));
            }
            for (namespace, services) in &host.service_groups {
                validate_namespace(namespace)?;
                for (service, tree) in services {
                    validate_component(service)?;
                    validate_tree(host_name, namespace, service, &[], tree)?;
                }
            }
        }
        Ok(())
    }

    pub fn secret(&self, path: &SecretPath) -> Result<SecretSpec, SchemaError> {
        match self.leaf(path)? {
            LeafSpec::Stored(spec) => Ok(spec),
            LeafSpec::Generated(_) => Err(SchemaError::WrongKind(path.clone())),
        }
    }

    pub fn generated_secret(&self, path: &SecretPath) -> Result<GeneratedSecretSpec, SchemaError> {
        match self.leaf(path)? {
            LeafSpec::Generated(spec) => Ok(spec),
            LeafSpec::Stored(_) => Err(SchemaError::WrongKind(path.clone())),
        }
    }

    pub fn leaf(&self, path: &SecretPath) -> Result<LeafSpec, SchemaError> {
        let host = self.0.get(&path.0[0]).ok_or_else(|| missing(path))?;
        let services = host
            .service_groups
            .get(&path.0[1])
            .ok_or_else(|| missing(path))?;
        let mut node = services.get(&path.0[2]).ok_or_else(|| missing(path))?;
        for component in &path.0[3..] {
            node = match node {
                SecretNode::Branch(children) => {
                    children.get(component).ok_or_else(|| missing(path))?
                }
                SecretNode::Secret(_) | SecretNode::Generated(_) => return Err(missing(path)),
            };
        }
        match node {
            SecretNode::Branch(_) => Err(SchemaError::IsBranch(path.clone())),
            SecretNode::Secret(leaf) => Ok(LeafSpec::Stored(SecretSpec {
                path: path.clone(),
                recipient_public_keys: leaf.recipient_public_keys.clone(),
                recipient_ids: leaf.recipient_ids.clone(),
                destination: leaf.destination.clone(),
                consumer_units: leaf.consumer_units.clone(),
                generation: leaf.generation.clone(),
            })),
            SecretNode::Generated(leaf) => Ok(LeafSpec::Generated(GeneratedSecretSpec {
                path: path.clone(),
                recipient_public_keys: leaf.recipient_public_keys.clone(),
                recipient_ids: leaf.recipient_ids.clone(),
                generated_secret: leaf.generated_secret.clone(),
                consumer_units: leaf.consumer_units.clone(),
                generation: leaf.generation.clone(),
            })),
        }
    }
}

fn missing(path: &SecretPath) -> SchemaError {
    SchemaError::NotFound(path.clone())
}

fn synthetic_path(host: &str) -> SecretPath {
    SecretPath(vec![
        host.into(),
        "services".into(),
        "metadata".into(),
        "socket".into(),
    ])
}
