//! Which generated keys register into a public-key inventory.

use super::{Schema, SecretNode};

impl Schema {
    /// The identifiers of every generated key whose `registerAt` names
    /// `inventory`, across all hosts of the schema.
    pub fn registration_producers(&self, inventory: &str) -> Vec<String> {
        let mut producers = Vec::new();
        for (host, entry) in &self.0 {
            for (namespace, services) in &entry.service_groups {
                for (service, node) in services {
                    walk(
                        node,
                        &format!("{host}.{namespace}.{service}"),
                        inventory,
                        &mut producers,
                    );
                }
            }
        }
        producers
    }
}

fn walk(node: &SecretNode, path: &str, inventory: &str, producers: &mut Vec<String>) {
    match node {
        SecretNode::Branch(children) => {
            for (name, child) in children {
                walk(child, &format!("{path}.{name}"), inventory, producers);
            }
        }
        SecretNode::Generated(leaf)
            if leaf.generated_secret.register_at.as_deref() == Some(inventory) =>
        {
            producers.push(path.to_owned());
        }
        _ => {}
    }
}
