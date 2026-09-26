use super::*;

impl Model {
    pub fn visible_rows(&self) -> Vec<usize> {
        self.visible_tree_rows()
            .into_iter()
            .map(|row| row.index)
            .collect()
    }

    /// Which filters each value row passes, with the branch rows above it.
    fn row_checks(&self) -> Vec<(usize, Vec<usize>, RowChecks)> {
        let needle = self.search.to_ascii_lowercase();
        let mut result = Vec::new();
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
                // A value needed before install stays listed until it is stored.
                ViewFilter::Required => {
                    row.external_input_required || (row.required_for_install && !row.is_set)
                }
                ViewFilter::All => true,
                ViewFilter::Keys => {
                    matches!(row.category, RowCategory::Key | RowCategory::Operator)
                }
                ViewFilter::Passwords => row.category == RowCategory::Password,
                ViewFilter::PublicInfo => row.category == RowCategory::PublicInfo,
            };
            let audience = !self.human_only || row.human_facing;
            let facets = self
                .facets
                .iter()
                // A facet filters only rows it applies to; e.g. a whitelist of
                // users leaves system services visible.
                .all(|(attribute, facet)| {
                    attribute
                        .value(row)
                        .is_none_or(|value| facet.accepts(&value))
                });
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
                    .filter_map(|attribute| attribute.value(row))
                    .any(|value| value.to_ascii_lowercase().contains(&needle));
            result.push((
                index,
                ancestors.clone(),
                RowChecks {
                    category,
                    audience,
                    facets,
                    searchable,
                },
            ));
        }
        result
    }

    /// While searching: how many values match the search, and how many of
    /// those the type, audience, and attribute filters hide.
    pub fn search_summary(&self) -> Option<SearchSummary> {
        if self.search.is_empty() {
            return None;
        }
        let mut summary = SearchSummary::default();
        for (_, _, checks) in self.row_checks() {
            if !checks.searchable {
                continue;
            }
            summary.matches += 1;
            if !(checks.category && checks.audience && checks.facets) {
                summary.hidden += 1;
                summary.hidden_by_type += usize::from(!checks.category);
                summary.hidden_by_audience += usize::from(!checks.audience);
                summary.hidden_by_facets += usize::from(!checks.facets);
            }
        }
        Some(summary)
    }

    pub fn visible_tree_rows(&self) -> Vec<VisibleRow> {
        let mut kept = std::collections::BTreeSet::new();
        for (index, ancestors, checks) in self.row_checks() {
            if checks.category && checks.audience && checks.facets && checks.searchable {
                kept.insert(index);
                kept.extend(ancestors);
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
        self.hide_collapsed(result)
    }

    /// Drops the rows below collapsed groups. Rows are in pre-order, so a
    /// group's subtree is the run of following rows whose attribute path
    /// extends the group's. Chains of single-child groups share one row, so
    /// the path and not the depth decides membership.
    fn hide_collapsed(&self, rows: Vec<VisibleRow>) -> Vec<VisibleRow> {
        if self.active_collapsed().is_none_or(|set| set.is_empty()) {
            return rows;
        }
        let mut hidden_below: Option<&[String]> = None;
        rows.into_iter()
            .filter(|visible| {
                let row = &self.rows[visible.index];
                if hidden_below.is_some_and(|group| {
                    row.display_segments.len() > group.len()
                        && row.display_segments.starts_with(group)
                }) {
                    return false;
                }
                hidden_below = self
                    .is_collapsed(row)
                    .then_some(row.display_segments.as_slice());
                true
            })
            .collect()
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

struct RowChecks {
    category: bool,
    audience: bool,
    facets: bool,
    searchable: bool,
}

/// Search matches that other filters hide. One value can be hidden by more
/// than one filter, so the per-filter counts may add up to more than `hidden`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SearchSummary {
    pub matches: usize,
    pub hidden: usize,
    pub hidden_by_type: usize,
    pub hidden_by_audience: usize,
    pub hidden_by_facets: usize,
}

impl SearchSummary {
    pub fn text(&self) -> String {
        let mut text = format!(
            "{} {}",
            self.matches,
            if self.matches == 1 {
                "match"
            } else {
                "matches"
            }
        );
        if self.hidden > 0 {
            let reasons = [
                (self.hidden_by_type, "type"),
                (self.hidden_by_audience, "audience"),
                (self.hidden_by_facets, "attribute filters"),
            ]
            .into_iter()
            .filter(|(count, _)| *count > 0)
            .map(|(count, reason)| format!("{count} {reason}"))
            .collect::<Vec<_>>()
            .join(", ");
            text.push_str(&format!(" · {} hidden by filters ({reasons})", self.hidden));
        }
        text
    }
}
