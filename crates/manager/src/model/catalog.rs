use super::*;
use std::collections::BTreeSet;

impl Model {
    pub fn rebuild_tree(&mut self) {
        let identity = self.selection_identity();
        let leaves = self
            .rows
            .iter()
            .filter(|row| row.is_secret())
            .cloned()
            .collect();
        self.rows = crate::tree::reordered_rows(leaves, &self.tree_order);
        if !self.restore_selection(identity) {
            self.selected = 0;
        }
    }

    pub fn facet_values(&self, attribute: Attribute) -> BTreeSet<String> {
        self.rows
            .iter()
            .filter(|row| row.is_secret())
            .filter_map(|row| attribute.value(row))
            .collect()
    }

    pub fn facet(&self, attribute: Attribute) -> Facet {
        self.facets.get(&attribute).cloned().unwrap_or_default()
    }

    pub fn set_facet(&mut self, attribute: Attribute, facet: Facet) {
        self.facets.insert(attribute, facet);
        self.selected = 0;
    }

    pub fn tree_editor_attributes(&self) -> Vec<Attribute> {
        self.tree_order
            .iter()
            .copied()
            .chain(
                Attribute::GROUPING
                    .into_iter()
                    .filter(|attribute| !self.tree_order.contains(attribute)),
            )
            .collect()
    }
}
