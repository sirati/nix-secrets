//! Every value a host can request in one deployment.

use super::{Schema, SchemaError, SecretNode, SecretPath};

impl Schema {
    /// The canonical identifiers of every deployable leaf of `host`: stored
    /// values (including public information and derived values) and
    /// generated-secret tasks. Operator-only leaves are never deployed and
    /// are left out.
    pub fn deployable_identifiers(&self, host: &str) -> Result<Vec<String>, SchemaError> {
        let entry = self
            .0
            .get(host)
            .ok_or_else(|| SchemaError::InvalidComponent(format!("unknown host {host}")))?;
        let mut identifiers = Vec::new();
        for (namespace, services) in &entry.service_groups {
            for (service, node) in services {
                collect(
                    node,
                    &mut vec![host.to_owned(), namespace.clone(), service.clone()],
                    &mut identifiers,
                )?;
            }
        }
        Ok(identifiers)
    }
}

fn collect(
    node: &SecretNode,
    path: &mut Vec<String>,
    identifiers: &mut Vec<String>,
) -> Result<(), SchemaError> {
    match node {
        SecretNode::Branch(children) => {
            for (name, child) in children {
                path.push(name.clone());
                collect(child, path, identifiers)?;
                path.pop();
            }
        }
        SecretNode::Secret(_) | SecretNode::Generated(_) => {
            identifiers.push(SecretPath::new(path.clone())?.to_string());
        }
        SecretNode::Operator(_) => {}
    }
    Ok(())
}
