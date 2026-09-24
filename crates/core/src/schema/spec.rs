use super::*;

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
    pub external_input_required: bool,
    pub identity: Option<SecretIdentity>,
    pub presentation: Option<SecretPresentation>,
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
    pub external_input_required: bool,
    pub identity: Option<SecretIdentity>,
    pub presentation: Option<SecretPresentation>,
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
