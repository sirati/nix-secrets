use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;

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
    Secret(SecretLeaf),
    Branch(BTreeMap<String, SecretNode>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretLeaf {
    #[serde(rename = "recipientPublicKeys")]
    pub recipient_public_keys: Vec<String>,
    #[serde(rename = "recipientIds")]
    pub recipient_ids: Vec<String>,
    pub destination: Destination,
    #[serde(rename = "consumerUnits")]
    pub consumer_units: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub path: String,
    pub category: String,
    pub owner: String,
    pub group: String,
    pub mode: String,
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
    #[error("secret has no recipient public key: {0}")]
    MissingPublicKey(SecretPath),
    #[error("recipient key and identifier counts differ: {0}")]
    RecipientCount(SecretPath),
    #[error("invalid destination for {0}: {1}")]
    InvalidDestination(SecretPath, String),
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
                SecretNode::Secret(_) => return Err(missing(path)),
            };
        }
        match node {
            SecretNode::Branch(_) => Err(SchemaError::IsBranch(path.clone())),
            SecretNode::Secret(leaf) => Ok(SecretSpec {
                path: path.clone(),
                recipient_public_keys: leaf.recipient_public_keys.clone(),
                recipient_ids: leaf.recipient_ids.clone(),
                destination: leaf.destination.clone(),
                consumer_units: leaf.consumer_units.clone(),
            }),
        }
    }
}

fn validate_tree(
    host: &str,
    namespace: &str,
    service: &str,
    parents: &[String],
    node: &SecretNode,
) -> Result<(), SchemaError> {
    match node {
        SecretNode::Branch(children) => {
            for (name, child) in children {
                validate_component(name)?;
                let mut path = parents.to_vec();
                path.push(name.clone());
                validate_tree(host, namespace, service, &path, child)?;
            }
            Ok(())
        }
        SecretNode::Secret(leaf) => {
            let mut components = vec![host.into(), namespace.into(), service.into()];
            components.extend_from_slice(parents);
            let path = SecretPath(components);
            if leaf.recipient_public_keys.is_empty() {
                return Err(SchemaError::MissingPublicKey(path));
            }
            if leaf.recipient_public_keys.len() != leaf.recipient_ids.len() {
                return Err(SchemaError::RecipientCount(path));
            }
            let category = &leaf.destination.category;
            if !matches!(category.as_str(), "setup" | "service" | "backup") {
                return Err(SchemaError::InvalidDestination(
                    path,
                    "invalid category".into(),
                ));
            }
            let prefix = format!("/persistent/secrets/{service}/{category}/");
            if !leaf.destination.path.starts_with(&prefix) {
                return Err(SchemaError::InvalidDestination(
                    path,
                    format!("path must start with {prefix}"),
                ));
            }
            Ok(())
        }
    }
}

fn validate_component(component: &str) -> Result<(), SchemaError> {
    let valid = !component.is_empty()
        && component
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(SchemaError::InvalidComponent(component.into()))
    }
}

fn validate_namespace(namespace: &str) -> Result<(), SchemaError> {
    if namespace == "services"
        || (namespace.starts_with("user-") && namespace.ends_with("-services"))
    {
        Ok(())
    } else {
        Err(SchemaError::InvalidNamespace(namespace.into()))
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
