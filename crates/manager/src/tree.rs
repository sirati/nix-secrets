use nix_secrets_core::schema::SecretNode;
use nix_secrets_core::{Schema, SecretKind, ValueType};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    pub depth: usize,
    pub name: String,
    pub display_segments: Vec<String>,
    pub path: Option<String>,
    pub is_set: bool,
    pub is_task: bool,
    pub can_generate: bool,
    pub can_copy_public: bool,
    pub output_is_set: Option<bool>,
    pub description: Option<String>,
    pub category: RowCategory,
    pub human_facing: bool,
    pub external_input_required: bool,
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
        output.push(branch(0, host_name, vec![host_name.clone()]));
        for (namespace, services) in &host.service_groups {
            let namespace_path = vec![host_name.clone(), namespace.clone()];
            output.push(branch(1, namespace, namespace_path.clone()));
            let mut display = DisplayNode::default();
            for (service, node) in services {
                let labels = host
                    .metadata
                    .service_display_paths
                    .get(namespace)
                    .and_then(|paths| paths.get(service))
                    .cloned()
                    .unwrap_or_else(|| vec![service.clone()]);
                let mut cursor = &mut display;
                for label in labels {
                    cursor = cursor.children.entry(label).or_default();
                }
                cursor.service = Some((service.clone(), node.clone()));
            }
            emit_display(
                &display,
                host_name,
                namespace,
                2,
                &namespace_path,
                set_paths,
                public_ids,
                &mut output,
            );
        }
    }
    output
}

#[derive(Default)]
struct DisplayNode {
    children: BTreeMap<String, DisplayNode>,
    service: Option<(String, SecretNode)>,
}

fn emit_display(
    parent: &DisplayNode,
    host: &str,
    namespace: &str,
    depth: usize,
    display_path: &[String],
    set: &BTreeSet<String>,
    public_ids: &BTreeSet<String>,
    output: &mut Vec<Row>,
) {
    for (label, node) in &parent.children {
        let mut child_path = display_path.to_vec();
        child_path.push(label.clone());
        output.push(branch(depth, label, child_path.clone()));
        if let Some((service, tree)) = &node.service {
            visit(
                tree,
                &format!("{host}.{namespace}.{service}"),
                depth + 1,
                &child_path,
                set,
                public_ids,
                output,
            );
        }
        emit_display(
            node,
            host,
            namespace,
            depth + 1,
            &child_path,
            set,
            public_ids,
            output,
        );
    }
}

fn visit(
    node: &SecretNode,
    path: &str,
    depth: usize,
    display_path: &[String],
    set: &BTreeSet<String>,
    public_ids: &BTreeSet<String>,
    output: &mut Vec<Row>,
) {
    match node {
        SecretNode::Secret(leaf) => output.push(Row {
            depth: depth.saturating_sub(1),
            name: path.rsplit('.').next().unwrap_or(path).to_owned(),
            display_segments: child_path(display_path, path.rsplit('.').next().unwrap_or(path)),
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
            can_copy_public: leaf.destination.content_type.as_deref()
                == Some("openssh-private-key"),
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
            external_input_required: leaf.external_input_required,
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
                display_segments: child_path(display_path, path.rsplit('.').next().unwrap_or(path)),
                path: Some(path.to_owned()),
                is_set: set.contains(path),
                is_task: true,
                can_generate: leaf.value_type == Some(ValueType::Password),
                can_copy_public: false,
                output_is_set: None,
                description: leaf.description.clone(),
                category: RowCategory::Password,
                human_facing: leaf.human_facing,
                external_input_required: leaf.external_input_required,
            })
        }
        SecretNode::Generated(_) => {}
        SecretNode::Branch(children) => {
            visit_children(children, path, depth, display_path, set, public_ids, output);
        }
    }
}

fn visit_children(
    children: &BTreeMap<String, SecretNode>,
    parent: &str,
    depth: usize,
    display_path: &[String],
    set: &BTreeSet<String>,
    public_ids: &BTreeSet<String>,
    output: &mut Vec<Row>,
) {
    for (name, node) in children {
        let path = format!("{parent}.{name}");
        let child_display = child_path(display_path, name);
        if matches!(node, SecretNode::Branch(_)) {
            output.push(branch(depth, name, child_display.clone()));
            visit(
                node,
                &path,
                depth + 1,
                &child_display,
                set,
                public_ids,
                output,
            );
        } else {
            visit(
                node,
                &path,
                depth + 1,
                display_path,
                set,
                public_ids,
                output,
            );
        }
    }
}

fn child_path(parent: &[String], name: &str) -> Vec<String> {
    let mut result = parent.to_vec();
    result.push(name.to_owned());
    result
}

fn branch(depth: usize, name: &str, display_segments: Vec<String>) -> Row {
    Row {
        depth,
        name: name.to_owned(),
        display_segments,
        path: None,
        is_set: false,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Branch,
        human_facing: false,
        external_input_required: false,
    }
}

#[cfg(test)]
mod tests;
