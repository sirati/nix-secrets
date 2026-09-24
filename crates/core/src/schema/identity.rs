use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{Schema, SchemaError, SecretNode, SecretPath};

/// Semantic identity is independent of the stable dotted identifier used by
/// existing encrypted stores and target deployment manifests.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretIdentity {
    pub host: String,
    pub scope: String,
    #[serde(default)]
    pub user: Option<String>,
    pub service: String,
    pub responsibility: String,
    #[serde(default)]
    pub namespace: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPresentation {
    pub explanation: String,
    pub facing: String,
    #[serde(rename = "type")]
    pub value_type: String,
}

impl Schema {
    /// Resolve the semantic identity to the stable identifier used on the wire
    /// and in existing encrypted TOML. Tree presentation never changes it.
    pub fn resolve_identity(
        &self,
        identity: &SecretIdentity,
    ) -> Result<Option<SecretPath>, SchemaError> {
        Ok(self.identity_index()?.remove(identity))
    }

    pub fn identity_index(&self) -> Result<BTreeMap<SecretIdentity, SecretPath>, SchemaError> {
        let mut index = BTreeMap::new();
        for (host, entry) in &self.0 {
            for (scope, services) in &entry.service_groups {
                for (service, node) in services {
                    let mut path = vec![host.clone(), scope.clone(), service.clone()];
                    collect(node, &mut path, &mut index)?;
                }
            }
        }
        Ok(index)
    }
}

fn collect(
    node: &SecretNode,
    path: &mut Vec<String>,
    index: &mut BTreeMap<SecretIdentity, SecretPath>,
) -> Result<(), SchemaError> {
    match node {
        SecretNode::Branch(children) => {
            for (name, child) in children {
                path.push(name.clone());
                collect(child, path, index)?;
                path.pop();
            }
        }
        SecretNode::Secret(leaf) => insert(
            leaf.identity.as_ref(),
            leaf.presentation.as_ref(),
            path,
            index,
        )?,
        SecretNode::Generated(leaf) => insert(
            leaf.identity.as_ref(),
            leaf.presentation.as_ref(),
            path,
            index,
        )?,
    }
    Ok(())
}

fn insert(
    identity: Option<&SecretIdentity>,
    presentation: Option<&SecretPresentation>,
    path: &[String],
    index: &mut BTreeMap<SecretIdentity, SecretPath>,
) -> Result<(), SchemaError> {
    let Some(identity) = identity else {
        return Ok(());
    };
    let stable = SecretPath::new(path.to_vec())?;
    let valid = identity.host == path[0]
        && match path[1].as_str() {
            "services" => identity.scope == "system" && identity.user.is_none(),
            namespace if namespace.starts_with("user-") && namespace.ends_with("-services") => {
                identity.scope == "user"
                    && identity.user.as_deref()
                        == Some(&namespace[5..namespace.len() - "-services".len()])
            }
            _ => false,
        }
        && [
            identity.service.as_str(),
            identity.responsibility.as_str(),
            identity.name.as_str(),
        ]
        .iter()
        .all(|value| valid_label(value))
        && identity.namespace.as_deref().is_none_or(valid_label);
    if !valid {
        return Err(SchemaError::InvalidValueDefinition(
            stable,
            "invalid semantic identity".into(),
        ));
    }
    if presentation.is_some_and(|value| {
        !valid_label(&value.facing)
            || !valid_label(&value.value_type)
            || value.explanation.len() > 2048
            || value.explanation.chars().any(char::is_control)
    }) {
        return Err(SchemaError::InvalidValueDefinition(
            stable,
            "invalid presentation metadata".into(),
        ));
    }
    if index.insert(identity.clone(), stable.clone()).is_some() {
        return Err(SchemaError::InvalidValueDefinition(
            stable,
            "duplicate semantic identity".into(),
        ));
    }
    Ok(())
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
