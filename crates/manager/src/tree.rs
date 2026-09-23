use nix_secrets_core::schema::SecretNode;
use nix_secrets_core::{Schema, SecretKind, ValueType};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub depth: usize,
    pub name: String,
    pub path: Option<String>,
    pub is_set: bool,
    pub is_task: bool,
    pub can_generate: bool,
    pub output_is_set: Option<bool>,
    pub description: Option<String>,
    pub category: RowCategory,
    pub human_facing: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowCategory {
    Branch,
    Password,
    Key,
    PublicInfo,
    Other,
}

impl Row {
    pub fn is_secret(&self) -> bool {
        self.path.is_some()
    }

    pub fn is_task(&self) -> bool {
        self.is_task
    }
}

pub fn rows(configuration: &Schema, set_paths: &BTreeSet<String>) -> Vec<Row> {
    rows_with_public(configuration, set_paths, &BTreeSet::new())
}

pub fn rows_with_public(
    configuration: &Schema,
    set_paths: &BTreeSet<String>,
    public_ids: &BTreeSet<String>,
) -> Vec<Row> {
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
                    public_ids,
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
    public_ids: &BTreeSet<String>,
    output: &mut Vec<Row>,
) {
    match node {
        SecretNode::Secret(leaf) => output.push(Row {
            depth: depth.saturating_sub(1),
            name: path.rsplit('.').next().unwrap_or(path).to_owned(),
            path: Some(path.to_owned()),
            is_set: if matches!(leaf.kind, SecretKind::PublicInfo) {
                leaf.shared_public_id
                    .as_ref()
                    .is_some_and(|id| public_ids.contains(id))
            } else {
                set.contains(path)
            },
            is_task: false,
            can_generate: leaf.value_type == Some(ValueType::Password),
            output_is_set: None,
            description: leaf.description.clone(),
            category: if matches!(leaf.kind, SecretKind::PublicInfo) {
                RowCategory::PublicInfo
            } else {
                match leaf.value_type {
                    Some(ValueType::Password) => RowCategory::Password,
                    Some(ValueType::Key) => RowCategory::Key,
                    None => RowCategory::Other,
                }
            },
            human_facing: leaf.human_facing,
        }),
        SecretNode::Generated(leaf)
            if matches!(
                leaf.generated_secret.secret_type,
                nix_secrets_core::GeneratedSecretType::StorageBoxSshKey
            ) =>
        {
            output.push(Row {
                depth: depth.saturating_sub(1),
                name: path.rsplit('.').next().unwrap_or(path).to_owned(),
                path: Some(path.to_owned()),
                is_set: set.contains(path),
                is_task: true,
                can_generate: leaf.value_type == Some(ValueType::Password),
                output_is_set: None,
                description: leaf.description.clone(),
                category: RowCategory::Password,
                human_facing: leaf.human_facing,
            })
        }
        SecretNode::Generated(_) => {}
        SecretNode::Branch(children) => {
            visit_children(children, path, depth, set, public_ids, output);
        }
    }
}

fn visit_children(
    children: &BTreeMap<String, SecretNode>,
    parent: &str,
    depth: usize,
    set: &BTreeSet<String>,
    public_ids: &BTreeSet<String>,
    output: &mut Vec<Row>,
) {
    for (name, node) in children {
        let path = format!("{parent}.{name}");
        if matches!(node, SecretNode::Branch(_)) {
            output.push(branch(depth, name));
        }
        visit(node, &path, depth + 1, set, public_ids, output);
    }
}

fn branch(depth: usize, name: &str) -> Row {
    Row {
        depth,
        name: name.to_owned(),
        path: None,
        is_set: false,
        is_task: false,
        can_generate: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Branch,
        human_facing: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_sorted_tree_and_marks_set_leaves() {
        let schema = Schema::from_json(r#"{"host":{"metadata":{"socketPath":"/run/s","deployment":{"host":"host","destination":"nix-secrets-forward@host","port":22}},"services":{"mail":{"password":{"kind":"secret","recipientPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"],"recipientIds":["key"],"destination":{"path":"/persistent/secrets/mail/service/password","category":"service","owner":"mail","group":"mail","mode":"0400"},"consumerUnits":[]}}}}}"#).unwrap();
        let set = BTreeSet::from(["host.services.mail.password".into()]);
        let rows = rows(&schema, &set);
        assert_eq!(
            rows.last().unwrap(),
            &Row {
                depth: 3,
                name: "password".into(),
                path: Some("host.services.mail.password".into()),
                is_set: true,
                is_task: false,
                can_generate: false,
                output_is_set: None,
                description: None,
                category: RowCategory::Other,
                human_facing: false,
            }
        );
    }

    #[test]
    fn generated_leaf_is_a_task_with_separate_output_status() {
        let schema = Schema::from_json(r#"{"host":{"metadata":{"socketPath":"/run/s","deployment":{"host":"host","destination":"nix-secrets-forward@host","port":22}},"services":{"backup":{"bootstrap":{"kind":"generated","recipientPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"],"recipientIds":["key"],"consumerUnits":[],"generatedSecret":{"type":"storage-box-ssh-key","output":{"path":"/persistent/secrets/backup/backup/key","category":"backup","owner":"backup","group":"backup","mode":"0400"},"bootstrap":{"host":"box","port":23,"user":"u","hostPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"]}}}}}}}"#).unwrap();
        let set = BTreeSet::from(["host.services.backup.bootstrap".into()]);
        let row = rows(&schema, &set).pop().unwrap();
        assert!(row.is_task());
        assert!(row.is_set);
        assert_eq!(row.output_is_set, None);
    }

    #[test]
    fn target_generated_local_key_is_not_an_editable_row() {
        let mut schema: serde_json::Value = serde_json::from_str(r#"{"host":{"metadata":{"socketPath":"/run/s","deployment":{"host":"host","destination":"secrets@host","port":22}},"services":{"mail":{"ssh-private-key":{"kind":"generated","recipientPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"],"recipientIds":["key"],"consumerUnits":[],"generatedSecret":{"type":"local-ssh-key","output":{"path":"/persistent/secrets/mail/service/ssh-private-key","category":"service","owner":"mail","group":"mail","mode":"0400","contentType":"openssh-private-key"}}}}}}}"#).unwrap();
        schema["host"]["services"]["mail"]["ssh-private-key"]["description"] =
            "Generated on target".into();
        let schema = Schema::from_json(&schema.to_string()).unwrap();
        assert!(rows(&schema, &BTreeSet::new())
            .iter()
            .all(|row| row.path.is_none()));
    }
}
