use super::*;
use crate::model::Attribute;

#[derive(Default)]
struct Node {
    children: BTreeMap<String, Node>,
    leaves: Vec<Row>,
}

pub fn reordered_rows(leaves: Vec<Row>, order: &[Attribute]) -> Vec<Row> {
    let mut root = Node::default();
    for leaf in leaves.into_iter().filter(Row::is_secret) {
        let mut cursor = &mut root;
        for (position, attribute) in order.iter().enumerate() {
            if *attribute == Attribute::Name && position + 1 == order.len() {
                continue;
            }
            // An inapplicable attribute adds no level: the row joins the parent group.
            if let Some(value) = attribute.value(&leaf) {
                cursor = cursor.children.entry(value).or_default();
            }
        }
        cursor.leaves.push(leaf);
    }
    let mut result = Vec::new();
    emit(root, 0, &mut Vec::new(), &mut result);
    result
}

fn emit(node: Node, depth: usize, ancestors: &mut Vec<String>, output: &mut Vec<Row>) {
    for (label, child) in node.children {
        ancestors.push(label.clone());
        output.push(branch(depth, &label, ancestors.clone()));
        emit(child, depth + 1, ancestors, output);
        ancestors.pop();
    }
    let mut leaves = node.leaves;
    leaves.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));
    for mut leaf in leaves {
        leaf.depth = depth;
        leaf.display_segments = child_path(ancestors, &leaf.name);
        output.push(leaf);
    }
}
