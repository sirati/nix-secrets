//! Operator-only secrets: stored encrypted for the operator, never deployed.

use serde::{Deserialize, Serialize};

use super::{SecretIdentity, SecretPresentation};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorLeaf {
    pub kind: OperatorKind,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "humanFacing", default)]
    pub human_facing: bool,
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
    #[serde(default)]
    pub generator: Option<KeypairGenerator>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OperatorKind {
    #[serde(rename = "operator")]
    Operator,
}

/// A keypair generator the operator runs locally: `nix run <installable> --
/// <args>`. It writes the private key to stdout and the public key to file
/// descriptor 3, and nothing else.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeypairGenerator {
    pub installable: String,
    #[serde(default)]
    pub args: Vec<String>,
}

pub const MAX_GENERATOR_ARGS: usize = 64;
pub const MAX_GENERATOR_ARG_BYTES: usize = 4096;

impl KeypairGenerator {
    pub fn validate_definition(&self) -> Result<(), String> {
        let printable = |value: &str| !value.chars().any(char::is_control);
        if self.installable.is_empty()
            || self.installable.len() > MAX_GENERATOR_ARG_BYTES
            || !printable(&self.installable)
            || self.installable.starts_with('-')
        {
            return Err("generator installable must be a printable flake reference".into());
        }
        if self.args.len() > MAX_GENERATOR_ARGS
            || self
                .args
                .iter()
                .any(|arg| arg.len() > MAX_GENERATOR_ARG_BYTES || arg.contains('\0'))
        {
            return Err(format!(
                "generator takes at most {MAX_GENERATOR_ARGS} arguments of at most {MAX_GENERATOR_ARG_BYTES} bytes without NUL"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct OperatorSpec {
    pub path: super::SecretPath,
    pub description: Option<String>,
    pub human_facing: bool,
    pub identity: Option<SecretIdentity>,
    pub presentation: Option<SecretPresentation>,
    pub recipient_public_keys: Vec<String>,
    pub recipient_ids: Vec<String>,
    pub recipient_names: Vec<String>,
    pub generator: Option<KeypairGenerator>,
}
