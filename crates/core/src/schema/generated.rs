use serde::{Deserialize, Serialize};

use super::{Destination, GenerationPolicy};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedSecretLeaf {
    pub kind: GeneratedKind,
    #[serde(rename = "recipientPublicKeys")]
    pub recipient_public_keys: Vec<String>,
    #[serde(rename = "recipientIds")]
    pub recipient_ids: Vec<String>,
    #[serde(rename = "generatedSecret")]
    pub generated_secret: GeneratedSecret,
    #[serde(rename = "consumerUnits")]
    pub consumer_units: Vec<String>,
    pub generation: Option<GenerationPolicy>,
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
    pub bootstrap: StorageBoxBootstrap,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum GeneratedSecretType {
    #[serde(rename = "storage-box-ssh-key")]
    StorageBoxSshKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBoxBootstrap {
    pub host: String,
    pub port: u16,
    pub user: String,
    #[serde(rename = "hostPublicKeys")]
    pub host_public_keys: Vec<String>,
}
