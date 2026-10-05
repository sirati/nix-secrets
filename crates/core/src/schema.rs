use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

mod errors;
mod generated;
mod identity;
mod spec;
pub use errors::{SchemaError, SchemaLoadError};
pub use spec::{GeneratedSecretSpec, LeafSpec, SecretSpec};
mod path;
mod registry;
use registry::{missing, synthetic_path, validate_named_recipients, validate_shared_public_specs};
pub mod derived;
mod deployable;
mod producers;
pub mod operator;
pub use derived::DerivedFrom;
pub(crate) mod validation;
mod value;
pub use operator::{KeypairGenerator, OperatorKind, OperatorLeaf, OperatorSpec};
pub mod value_generator;
pub use generated::{
    GeneratedKind, GeneratedSecret, GeneratedSecretLeaf, GeneratedSecretType, StorageBoxBootstrap,
};
pub use identity::{SecretIdentity, SecretPresentation};
pub use validation::{known_hosts_keys, validate_ssh_known_hosts, MAX_KNOWN_HOSTS_BYTES};
use validation::{validate_component, validate_namespace, validate_tree};
pub use value::{ConsumerConstraints, ValueType};
pub use value_generator::{
    DeployGenerator, NotGeneratable, RandomEncoding, ValueGenerator, deployment_generator,
};

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
    /// Publish only the identity verified for a successful deployment.
    #[serde(rename = "publishHostIdentityTo", default, skip_serializing_if = "Option::is_none")]
    pub publish_host_identity_to: Option<String>,
    pub host: String,
    pub destination: String,
    pub port: u16,
    /// The public keys the target's forwarder account authorizes. The
    /// deployment SSH offers only these, so an agent holding many keys is
    /// not cut off by the server's MaxAuthTries before the right one.
    #[serde(rename = "identityPublicKeys", default, skip_serializing_if = "Vec::is_empty")]
    pub identity_public_keys: Vec<String>,
    /// The deployment protocol the host's receiver speaks, when known from
    /// its configuration.
    #[serde(rename = "protocolVersion", default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u16>,
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
    /// Operator-only: never part of a host manifest or deployment.
    Operator(OperatorLeaf),
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
    /// Further hosts the known_hosts value may name, such as one host per
    /// Storage Box sub-account; together with `expected_ssh_host`.
    #[serde(rename = "expectedSshHosts", default, skip_serializing_if = "Vec::is_empty")]
    pub expected_ssh_hosts: Vec<String>,
    #[serde(rename = "installDefaultIfMissing", default)]
    pub install_default_if_missing: bool,
    /// Public information only: the value used while the store has none. The
    /// host installs it when `installDefaultIfMissing` is set, and a
    /// deployment sends it.
    #[serde(rename = "defaultValue", default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "humanFacing", default)]
    pub human_facing: bool,
    #[serde(rename = "externalInputRequired", default)]
    pub external_input_required: bool,
    /// The host cannot be installed until this value is stored.
    #[serde(rename = "requiredForInstall", default)]
    pub required_for_install: bool,
    /// Absent values do not hold consumers or trigger deployment generation.
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub identity: Option<SecretIdentity>,
    #[serde(default)]
    pub presentation: Option<SecretPresentation>,
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
    #[serde(rename = "valueGenerator", default)]
    pub value_generator: Option<ValueGenerator>,
    #[serde(rename = "generateOnDeploy", default = "default_true")]
    pub generate_on_deploy: bool,
    /// Deployed as `prefix + <source value> + suffix`; never stored itself.
    #[serde(rename = "derivedFrom", default)]
    pub derived_from: Option<DerivedFrom>,
}

fn default_true() -> bool {
    true
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

impl Schema {
    pub fn from_json(input: &str) -> Result<Self, SchemaLoadError> {
        let schema: Self = serde_json::from_str(input)?;
        schema.validate()?;
        Ok(schema)
    }

    pub fn validate(&self) -> Result<(), SchemaError> {
        self.identity_index()?;
        self.validate_derived()?;
        let mut identity_producers = BTreeMap::<String, String>::new();
        let mut public_specs = BTreeMap::<String, (Vec<String>, u16)>::new();
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
            if let Some(identifier) = &host.metadata.deployment.publish_host_identity_to {
                let path = SecretPath::parse(identifier)?;
                let spec = self.secret(&path)?;
                if !matches!(spec.kind, SecretKind::PublicInfo)
                    || spec.shared_public_id.is_none()
                    || spec.expected_ssh_port.is_none()
                    || path.components().first() != Some(host_name)
                {
                    return Err(SchemaError::InvalidDestination(path,
                        "publishHostIdentityTo requires this producer's shared public-info leaf".into()));
                }
                let shared = spec.shared_public_id.expect("checked above");
                if identity_producers.insert(shared, host_name.clone()).is_some() {
                    return Err(SchemaError::InvalidDestination(path,
                        "shared host identity has more than one producer".into()));
                }
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
            LeafSpec::Generated(_) | LeafSpec::Operator(_) => {
                Err(SchemaError::WrongKind(path.clone()))
            }
        }
    }

    pub fn generated_secret(&self, path: &SecretPath) -> Result<GeneratedSecretSpec, SchemaError> {
        match self.leaf(path)? {
            LeafSpec::Generated(spec) => Ok(spec),
            LeafSpec::Stored(_) | LeafSpec::Operator(_) => {
                Err(SchemaError::WrongKind(path.clone()))
            }
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
                SecretNode::Secret(_) | SecretNode::Generated(_) | SecretNode::Operator(_) => {
                    return Err(missing(path));
                }
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
                expected_ssh_hosts: leaf.expected_ssh_hosts.clone(),
                install_default_if_missing: leaf.install_default_if_missing,
                default_value: leaf.default_value.clone(),
                description: leaf.description.clone(),
                human_facing: leaf.human_facing,
                external_input_required: leaf.external_input_required,
                optional: leaf.optional,
                identity: leaf.identity.clone(),
                presentation: leaf.presentation.clone(),
                recipient_public_keys: leaf.recipient_public_keys.clone(),
                recipient_ids: leaf.recipient_ids.clone(),
                recipient_names: leaf.recipient_names.clone(),
                destination: leaf.destination.clone(),
                consumer_units: leaf.consumer_units.clone(),
                value_type: leaf.value_type,
                consumer_constraints: leaf.consumer_constraints.clone(),
                value_generator: leaf.value_generator.clone(),
                generate_on_deploy: leaf.generate_on_deploy,
                derived_from: leaf.derived_from.clone(),
            })),
            SecretNode::Operator(leaf) => Ok(LeafSpec::Operator(OperatorSpec {
                signing_only: leaf.signing_only,
                path: path.clone(),
                description: leaf.description.clone(),
                human_facing: leaf.human_facing,
                identity: leaf.identity.clone(),
                presentation: leaf.presentation.clone(),
                recipient_public_keys: leaf.recipient_public_keys.clone(),
                recipient_ids: leaf.recipient_ids.clone(),
                recipient_names: leaf.recipient_names.clone(),
                generator: leaf.generator.clone(),
            })),
            SecretNode::Generated(leaf) => Ok(LeafSpec::Generated(GeneratedSecretSpec {
                path: path.clone(),
                description: leaf.description.clone(),
                human_facing: leaf.human_facing,
                external_input_required: leaf.external_input_required,
                optional: leaf.optional,
                identity: leaf.identity.clone(),
                presentation: leaf.presentation.clone(),
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
