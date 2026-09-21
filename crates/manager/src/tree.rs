use nix_secrets_core::schema::SecretNode;
use nix_secrets_core::Schema;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub depth: usize,
    pub name: String,
    pub path: Option<String>,
    pub is_set: bool,
}

impl Row {
    pub fn is_secret(&self) -> bool {
        self.path.is_some()
    }
}

pub fn rows(configuration: &Schema, set_paths: &BTreeSet<String>) -> Vec<Row> {
    let mut output = Vec::new();
    for (host_name, host) in &configuration.0 {
        output.push(branch(0, host_name));
        for (namespace, services) in &host.service_groups {
            output.push(branch(1, namespace));
            for (service, node) in services {
                output.push(branch(2, service));
                visit(
                    node,
                    &format!("{host_name}.{namespace}.{service}"),
                    3,
                    set_paths,
                    &mut output,
                );
            }
        }
    }
    output
}

fn visit(
    node: &SecretNode,
    path: &str,
    depth: usize,
    set: &BTreeSet<String>,
    output: &mut Vec<Row>,
) {
    match node {
        SecretNode::Secret(_) => output.push(Row {
            depth: depth.saturating_sub(1),
            name: path.rsplit('.').next().unwrap_or(path).to_owned(),
            path: Some(path.to_owned()),
            is_set: set.contains(path),
        }),
        SecretNode::Branch(children) => {
            visit_children(children, path, depth, set, output);
        }
    }
}

fn visit_children(
    children: &BTreeMap<String, SecretNode>,
    parent: &str,
    depth: usize,
    set: &BTreeSet<String>,
    output: &mut Vec<Row>,
) {
    for (name, node) in children {
        let path = format!("{parent}.{name}");
        if matches!(node, SecretNode::Branch(_)) {
            output.push(branch(depth, name));
        }
        visit(node, &path, depth + 1, set, output);
    }
}

fn branch(depth: usize, name: &str) -> Row {
    Row {
        depth,
        name: name.to_owned(),
        path: None,
        is_set: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_sorted_tree_and_marks_set_leaves() {
        let schema = Schema::from_json(r#"{"host":{"metadata":{"socketPath":"/run/s","deployment":{"host":"host","destination":"nix-secrets-forward@host","port":22}},"services":{"mail":{"password":{"recipientPublicKeys":["ssh-ed25519 AAAA"],"recipientIds":["key"],"destination":{"path":"/persistent/secrets/mail/service/password","category":"service","owner":"mail","group":"mail","mode":"0400"},"consumerUnits":[]}}}}}"#).unwrap();
        let set = BTreeSet::from(["host.services.mail.password".into()]);
        let rows = rows(&schema, &set);
        assert_eq!(
            rows.last().unwrap(),
            &Row {
                depth: 3,
                name: "password".into(),
                path: Some("host.services.mail.password".into()),
                is_set: true
            }
        );
    }
}
