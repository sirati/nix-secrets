use super::*;

impl Model {
    pub fn visible_rows(&self) -> Vec<usize> {
        self.visible_tree_rows()
            .into_iter()
            .map(|row| row.index)
            .collect()
    }

    pub fn visible_tree_rows(&self) -> Vec<VisibleRow> {
        let needle = self.search.to_ascii_lowercase();
        let mut kept = std::collections::BTreeSet::new();
        let mut ancestors: Vec<usize> = Vec::new();
        for (index, row) in self.rows.iter().enumerate() {
            while ancestors
                .last()
                .is_some_and(|parent| self.rows[*parent].depth >= row.depth)
            {
                ancestors.pop();
            }
            if row.path.is_none() {
                ancestors.push(index);
                continue;
            }
            let category = match self.filter {
                ViewFilter::Required => row.external_input_required,
                ViewFilter::All => true,
                ViewFilter::Keys => row.category == RowCategory::Key,
                ViewFilter::Passwords => row.category == RowCategory::Password,
                ViewFilter::PublicInfo => row.category == RowCategory::PublicInfo,
            };
            let audience = !self.human_only || row.human_facing;
            let facets = self
                .facets
                .iter()
                .all(|(attribute, facet)| facet.accepts(&attribute.value(row)));
            let searchable = std::iter::once(row.name.as_str())
                .chain(row.path.as_deref())
                .chain(row.description.as_deref())
                .chain(
                    ancestors
                        .iter()
                        .map(|parent| self.rows[*parent].name.as_str()),
                )
                .any(|value| value.to_ascii_lowercase().contains(&needle))
                || Attribute::ALL
                    .iter()
                    .any(|attribute| attribute.value(row).to_ascii_lowercase().contains(&needle));
            if category && audience && facets && searchable {
                kept.insert(index);
                kept.extend(ancestors.iter().copied());
            }
        }
        let raw = kept.into_iter().collect::<Vec<_>>();
        let mut result: Vec<VisibleRow> = Vec::new();
        for (position, index) in raw.iter().copied().enumerate() {
            let row = &self.rows[index];
            let direct_children = raw
                .iter()
                .copied()
                .skip(position + 1)
                .take_while(|candidate| self.rows[*candidate].depth > row.depth)
                .filter(|candidate| self.rows[*candidate].depth == row.depth + 1)
                .count();
            if row.path.is_none() && row.depth >= 2 && direct_children == 1 {
                continue;
            }
            let mut labels = vec![row.name.clone()];
            let mut depth = row.depth;
            for parent in raw[..position].iter().rev().copied() {
                let parent_row = &self.rows[parent];
                if parent_row.depth >= depth {
                    continue;
                }
                let parent_position = raw
                    .iter()
                    .position(|candidate| *candidate == parent)
                    .unwrap();
                let siblings = raw
                    .iter()
                    .copied()
                    .skip(parent_position + 1)
                    .take_while(|candidate| self.rows[*candidate].depth > parent_row.depth)
                    .filter(|candidate| self.rows[*candidate].depth == parent_row.depth + 1)
                    .count();
                if siblings != 1 || parent_row.depth < 2 {
                    break;
                }
                labels.insert(0, parent_row.name.clone());
                depth = parent_row.depth;
            }
            result.push(VisibleRow {
                index,
                depth,
                label: labels.join("/"),
            });
        }
        result
    }

    pub fn selected_display_path(&self) -> Option<String> {
        let visible = self.visible_tree_rows();
        let current = visible.get(self.selected)?;
        let selected_row = &self.rows[current.index];
        if let Some(identity) = &selected_row.identity {
            let mut parts = vec![identity.host.as_str(), identity.scope.as_str()];
            if let Some(user) = identity.user.as_deref() {
                parts.push(user);
            }
            parts.extend([identity.service.as_str(), identity.responsibility.as_str()]);
            if let Some(namespace) = identity.namespace.as_deref() {
                parts.push(namespace);
            }
            parts.push(identity.name.as_str());
            return Some(parts.join(" > "));
        }
        if selected_row.display_segments.is_empty() {
            return Some(current.label.clone());
        }
        let mut parts = visible[..self.selected]
            .iter()
            .filter(|candidate| {
                let row = &self.rows[candidate.index];
                row.path.is_none()
                    && row.display_segments.len() < selected_row.display_segments.len()
                    && selected_row
                        .display_segments
                        .starts_with(&row.display_segments)
            })
            .map(|candidate| candidate.label.as_str())
            .collect::<Vec<_>>();
        parts.push(&current.label);
        Some(parts.join(" > "))
    }
}
