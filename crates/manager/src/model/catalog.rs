use super::*;
use std::collections::BTreeSet;

impl Model {
    pub fn rebuild_tree(&mut self) {
        let selected_path = self.selected().and_then(|row| row.path.clone());
        let leaves = self
            .rows
            .iter()
            .filter(|row| row.is_secret())
            .cloned()
            .collect();
        self.rows = crate::tree::reordered_rows(leaves, &self.tree_order);
        self.selected = selected_path
            .and_then(|path| {
                self.visible_rows()
                    .iter()
                    .position(|index| self.rows[*index].path.as_deref() == Some(path.as_str()))
            })
            .unwrap_or(0);
    }

    pub fn facet_values(&self, attribute: Attribute) -> BTreeSet<String> {
        self.rows
            .iter()
            .filter(|row| row.is_secret())
            .map(|row| attribute.value(row))
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
                Attribute::ALL
                    .into_iter()
                    .filter(|attribute| !self.tree_order.contains(attribute)),
            )
            .collect()
    }
}
