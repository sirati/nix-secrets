//! Collapsible tree groups.
//!
//! A group is identified by its `display_segments`, the path of attribute
//! values from the root, never by its row index. That identity survives
//! backend refreshes, value changes, and filters; after a tree-order change a
//! group with the same path of values is still collapsed. State lives only in
//! this session and is never written to profiles.
//!
//! While a search is active the stored state is suspended: every group that
//! contains a match is shown expanded, and groups can be folded within the
//! results. Those folds last until the query changes; clearing the search
//! restores the state from before it.
use super::*;
use std::collections::BTreeSet;

impl Model {
    /// The collapsed groups that apply to the current view.
    pub(super) fn active_collapsed(&self) -> Option<&BTreeSet<Vec<String>>> {
        if self.search.is_empty() {
            Some(&self.collapsed)
        } else if self.search_collapsed.0 == self.search {
            Some(&self.search_collapsed.1)
        } else {
            None
        }
    }

    fn active_collapsed_mut(&mut self) -> &mut BTreeSet<Vec<String>> {
        if self.search.is_empty() {
            return &mut self.collapsed;
        }
        if self.search_collapsed.0 != self.search {
            self.search_collapsed = (self.search.clone(), BTreeSet::new());
        }
        &mut self.search_collapsed.1
    }

    pub fn is_collapsed(&self, row: &Row) -> bool {
        !row.is_secret()
            && self
                .active_collapsed()
                .is_some_and(|set| set.contains(&row.display_segments))
    }

    /// Collapses or expands the selected group. Returns false on a value.
    pub fn toggle_selected_group(&mut self) -> bool {
        let Some(row) = self.selected().filter(|row| !row.is_secret()) else {
            return false;
        };
        let key = row.display_segments.clone();
        let set = self.active_collapsed_mut();
        if !set.remove(&key) {
            set.insert(key);
        }
        true
    }

    /// Collapses every group, down to the top level.
    pub fn collapse_all(&mut self) {
        let anchor = self.selected_row_index();
        let groups = self
            .rows
            .iter()
            .filter(|row| !row.is_secret())
            .map(|row| row.display_segments.clone())
            .collect::<Vec<_>>();
        self.active_collapsed_mut().extend(groups);
        self.reselect(anchor);
    }

    pub fn expand_all(&mut self) {
        let anchor = self.selected_row_index();
        self.active_collapsed_mut().clear();
        self.reselect(anchor);
    }

    fn selected_row_index(&self) -> Option<usize> {
        self.visible_rows().get(self.selected).copied()
    }

    /// Selects row `anchor`, or else the collapsed group that hides it, or
    /// else the first row.
    pub(super) fn reselect(&mut self, anchor: Option<usize>) {
        self.selected = anchor
            .and_then(|anchor| self.visible_position_or_group(anchor))
            .unwrap_or(0);
    }

    fn visible_position_or_group(&self, anchor: usize) -> Option<usize> {
        let visible = self.visible_rows();
        if let Some(position) = visible.iter().position(|index| *index == anchor) {
            return Some(position);
        }
        let segments = &self.rows.get(anchor)?.display_segments;
        visible
            .iter()
            .enumerate()
            .filter(|(_, index)| {
                let row = &self.rows[**index];
                !row.is_secret()
                    && row.display_segments.len() < segments.len()
                    && segments.starts_with(&row.display_segments)
            })
            .max_by_key(|(_, index)| self.rows[**index].display_segments.len())
            .map(|(position, _)| position)
    }
}

/// What the selection points at, independent of row indices: a value by its
/// path, a group by its path of attribute values.
pub(super) struct SelectionIdentity {
    path: Option<String>,
    segments: Vec<String>,
}

impl Model {
    pub(super) fn selection_identity(&self) -> Option<SelectionIdentity> {
        self.selected().map(|row| SelectionIdentity {
            path: row.path.clone(),
            segments: row.display_segments.clone(),
        })
    }

    /// Selects the same value or group after the rows were rebuilt, or else its
    /// deepest visible group, such as the collapsed group that now hides it. Returns false when it is gone.
    pub(super) fn restore_selection(&mut self, identity: Option<SelectionIdentity>) -> bool {
        let anchor = identity.and_then(|identity| {
            self.rows.iter().position(|row| match &identity.path {
                Some(path) => row.path.as_ref() == Some(path),
                None => !row.is_secret() && row.display_segments == identity.segments,
            })
        });
        match anchor.and_then(|anchor| self.visible_position_or_group(anchor)) {
            Some(position) => {
                self.selected = position;
                true
            }
            None => false,
        }
    }
}

impl SelectionIdentity {
    pub(super) fn is_value(&self) -> bool {
        self.path.is_some()
    }
}
