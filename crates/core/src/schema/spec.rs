use super::value_generator::ValueGenerator;
use super::*;

#[derive(Clone, Debug)]
pub struct SecretSpec {
    pub path: SecretPath,
    pub kind: SecretKind,
    pub shared_public_id: Option<String>,
    pub expected_ssh_host: Option<String>,
    pub expected_ssh_port: Option<u16>,
    pub expected_ssh_hosts: Vec<String>,
    pub install_default_if_missing: bool,
    pub default_value: Option<String>,
    pub description: Option<String>,
    pub human_facing: bool,
    pub external_input_required: bool,
    pub optional: bool,
    pub identity: Option<SecretIdentity>,
    pub presentation: Option<SecretPresentation>,
    pub recipient_public_keys: Vec<String>,
    pub recipient_ids: Vec<String>,
    pub recipient_names: Vec<String>,
    pub destination: Destination,
    pub consumer_units: Vec<String>,
    pub value_type: Option<ValueType>,
    pub consumer_constraints: Option<ConsumerConstraints>,
    pub value_generator: Option<ValueGenerator>,
    pub generate_on_deploy: bool,
    pub derived_from: Option<super::DerivedFrom>,
}

#[derive(Clone, Debug)]
pub struct GeneratedSecretSpec {
    pub path: SecretPath,
    pub description: Option<String>,
    pub human_facing: bool,
    pub external_input_required: bool,
    pub optional: bool,
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
    Operator(super::OperatorSpec),
}

impl LeafSpec {
    /// Encryption recipients as (identifier, SSH public key) pairs.
    pub fn recipients(&self) -> (&[String], &[String]) {
        match self {
            Self::Stored(spec) => (&spec.recipient_ids, &spec.recipient_public_keys),
            Self::Generated(spec) => (&spec.recipient_ids, &spec.recipient_public_keys),
            Self::Operator(spec) => (&spec.recipient_ids, &spec.recipient_public_keys),
        }
    }

    pub fn recipient_names(&self) -> &[String] {
        match self {
            Self::Stored(spec) => &spec.recipient_names,
            Self::Generated(spec) => &spec.recipient_names,
            Self::Operator(spec) => &spec.recipient_names,
        }
    }
}

impl SecretSpec {
    /// Every host a public-info known_hosts value may name.
    pub fn ssh_hosts(&self) -> Vec<&str> {
        ssh_hosts(self.expected_ssh_host.as_deref(), &self.expected_ssh_hosts)
    }
}

impl super::SecretLeaf {
    /// Every host a public-info known_hosts value may name.
    pub fn ssh_hosts(&self) -> Vec<&str> {
        ssh_hosts(self.expected_ssh_host.as_deref(), &self.expected_ssh_hosts)
    }
}

fn ssh_hosts<'a>(single: Option<&'a str>, more: &'a [String]) -> Vec<&'a str> {
    let mut hosts = single.into_iter().chain(more.iter().map(String::as_str)).collect::<Vec<_>>();
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}
