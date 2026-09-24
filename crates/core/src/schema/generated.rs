use serde::{Deserialize, Serialize};

use super::{ConsumerConstraints, Destination, SecretIdentity, SecretPresentation, ValueType};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedSecretLeaf {
    pub kind: GeneratedKind,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "humanFacing", default)]
    pub human_facing: bool,
    #[serde(rename = "externalInputRequired", default)]
    pub external_input_required: bool,
    #[serde(default)]
    pub identity: Option<SecretIdentity>,
    #[serde(default)]
    pub presentation: Option<SecretPresentation>,
    #[serde(rename = "recipientPublicKeys")]
    pub recipient_public_keys: Vec<String>,
    #[serde(rename = "recipientIds")]
    pub recipient_ids: Vec<String>,
    #[serde(rename = "recipientNames", default)]
    pub recipient_names: Vec<String>,
    #[serde(rename = "generatedSecret")]
    pub generated_secret: GeneratedSecret,
    #[serde(rename = "consumerUnits")]
    pub consumer_units: Vec<String>,
    #[serde(rename = "valueType", default)]
    pub value_type: Option<ValueType>,
    #[serde(rename = "consumerConstraints", default)]
    pub consumer_constraints: Option<ConsumerConstraints>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum GeneratedKind {
    #[serde(rename = "generated")]
    Generated,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedSecret {
    #[serde(rename = "type")]
    pub secret_type: GeneratedSecretType,
    pub output: Destination,
    pub bootstrap: Option<StorageBoxBootstrap>,
    #[serde(rename = "registerAt", default)]
    pub register_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GeneratedSecretType {
    #[serde(rename = "storage-box-ssh-key")]
    StorageBoxSshKey,
    #[serde(rename = "local-ssh-key")]
    LocalSshKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBoxBootstrap {
    pub host: String,
    pub port: u16,
    pub user: String,
    #[serde(rename = "hostPublicKeys")]
    #[serde(default)]
    pub host_public_keys: Vec<String>,
    #[serde(rename = "knownHostsFile", default)]
    pub known_hosts_file: Option<String>,
}
