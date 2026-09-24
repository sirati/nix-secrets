use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;

mod generated;
mod path;
mod registry;
use registry::{missing, synthetic_path, validate_named_recipients, validate_shared_public_specs};
pub(crate) mod validation;
mod value;
pub use generated::{
    GeneratedKind, GeneratedSecret, GeneratedSecretLeaf, GeneratedSecretType, StorageBoxBootstrap,
};
pub use validation::validate_ssh_known_hosts;
use validation::{validate_component, validate_namespace, validate_tree};
pub use value::{ConsumerConstraints, ValueType};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Schema(pub BTreeMap<String, HostSchema>);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMetadata {
    #[serde(rename = "socketPath")]
    pub socket_path: String,
    pub deployment: DeploymentMetadata,
    #[serde(rename = "recipientPublicKeys", default)]
    pub recipient_public_keys: BTreeMap<String, String>,
    #[serde(rename = "serviceDisplayPaths", default)]
    pub service_display_paths: BTreeMap<String, BTreeMap<String, Vec<String>>>,
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
    #[serde(rename = "sharedPublicId", default)]
    pub shared_public_id: Option<String>,
    #[serde(rename = "expectedSshHost", default)]
    pub expected_ssh_host: Option<String>,
    #[serde(rename = "expectedSshPort", default)]
    pub expected_ssh_port: Option<u16>,
    #[serde(rename = "installDefaultIfMissing", default)]
    pub install_default_if_missing: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "humanFacing", default)]
    pub human_facing: bool,
    #[serde(rename = "recipientPublicKeys", default)]
    pub recipient_public_keys: Vec<String>,
    #[serde(rename = "recipientIds", default)]
    pub recipient_ids: Vec<String>,
    #[serde(rename = "recipientNames", default)]
    pub recipient_names: Vec<String>,
    pub destination: Destination,
    #[serde(rename = "consumerUnits")]
    pub consumer_units: Vec<String>,
    #[serde(rename = "valueType", default)]
    pub value_type: Option<ValueType>,
    #[serde(rename = "consumerConstraints", default)]
    pub consumer_constraints: Option<ConsumerConstraints>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SecretKind {
    #[serde(rename = "secret")]
    Secret,
    #[serde(rename = "public-info")]
    PublicInfo,
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
    pub kind: SecretKind,
    pub shared_public_id: Option<String>,
    pub expected_ssh_host: Option<String>,
    pub expected_ssh_port: Option<u16>,
    pub install_default_if_missing: bool,
    pub description: Option<String>,
    pub human_facing: bool,
    pub recipient_public_keys: Vec<String>,
    pub recipient_ids: Vec<String>,
    pub recipient_names: Vec<String>,
    pub destination: Destination,
    pub consumer_units: Vec<String>,
    pub value_type: Option<ValueType>,
    pub consumer_constraints: Option<ConsumerConstraints>,
}

#[derive(Clone, Debug)]
pub struct GeneratedSecretSpec {
    pub path: SecretPath,
    pub description: Option<String>,
    pub human_facing: bool,
    pub recipient_public_keys: Vec<String>,
    pub recipient_ids: Vec<String>,
    pub recipient_names: Vec<String>,
    pub generated_secret: GeneratedSecret,
    pub consumer_units: Vec<String>,
    pub value_type: Option<ValueType>,
    pub consumer_constraints: Option<ConsumerConstraints>,
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

impl Schema {
    pub fn from_json(input: &str) -> Result<Self, SchemaLoadError> {
        let schema: Self = serde_json::from_str(input)?;
        schema.validate()?;
        Ok(schema)
    }

    pub fn validate(&self) -> Result<(), SchemaError> {
        let mut public_specs = BTreeMap::<String, (String, u16)>::new();
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
                    validate_named_recipients(
                        host_name,
                        tree,
                        &host.metadata.recipient_public_keys,
                    )?;
                    validate_shared_public_specs(host_name, tree, &mut public_specs)?;
                }
            }
            for (namespace, services) in &host.metadata.service_display_paths {
                validate_namespace(namespace)?;
                for (service, path) in services {
                    if !host
                        .service_groups
                        .get(namespace)
                        .is_some_and(|entries| entries.contains_key(service))
                        || path.is_empty()
                    {
                        return Err(SchemaError::InvalidComponent(format!(
                            "unknown or empty display path for {namespace}.{service}"
                        )));
                    }
                    for component in path {
                        validate_component(component)?;
                    }
                }
            }
            for (namespace, services) in &host.service_groups {
                let paths = host.metadata.service_display_paths.get(namespace);
                let mut used = std::collections::BTreeSet::new();
                for service in services.keys() {
                    let path = paths
                        .and_then(|paths| paths.get(service))
                        .cloned()
                        .unwrap_or_else(|| vec![service.clone()]);
                    if !used.insert(path) {
                        return Err(SchemaError::InvalidComponent(format!(
                            "duplicate display path in {namespace}"
                        )));
                    }
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
                kind: leaf.kind.clone(),
                shared_public_id: leaf.shared_public_id.clone(),
                expected_ssh_host: leaf.expected_ssh_host.clone(),
                expected_ssh_port: leaf.expected_ssh_port,
                install_default_if_missing: leaf.install_default_if_missing,
                description: leaf.description.clone(),
                human_facing: leaf.human_facing,
                recipient_public_keys: leaf.recipient_public_keys.clone(),
                recipient_ids: leaf.recipient_ids.clone(),
                recipient_names: leaf.recipient_names.clone(),
                destination: leaf.destination.clone(),
                consumer_units: leaf.consumer_units.clone(),
                value_type: leaf.value_type,
                consumer_constraints: leaf.consumer_constraints.clone(),
            })),
            SecretNode::Generated(leaf) => Ok(LeafSpec::Generated(GeneratedSecretSpec {
                path: path.clone(),
                description: leaf.description.clone(),
                human_facing: leaf.human_facing,
                recipient_public_keys: leaf.recipient_public_keys.clone(),
                recipient_ids: leaf.recipient_ids.clone(),
                recipient_names: leaf.recipient_names.clone(),
                generated_secret: leaf.generated_secret.clone(),
                consumer_units: leaf.consumer_units.clone(),
                value_type: leaf.value_type,
                consumer_constraints: leaf.consumer_constraints.clone(),
            })),
        }
    }
}
