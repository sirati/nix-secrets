use crate::tree::{Row, RowCategory};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Attribute {
    Host,
    Scope,
    User,
    Service,
    Responsibility,
    Namespace,
    Name,
    Explanation,
    Facing,
    Type,
    Status,
}

impl Attribute {
    pub const ALL: [Self; 11] = [
        Self::Host,
        Self::Scope,
        Self::User,
        Self::Service,
        Self::Responsibility,
        Self::Namespace,
        Self::Name,
        Self::Explanation,
        Self::Facing,
        Self::Type,
        Self::Status,
    ];

    pub const DEFAULT_TREE: [Self; 6] = [
        Self::Host,
        Self::Scope,
        Self::Service,
        Self::Responsibility,
        Self::Namespace,
        Self::Name,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Host => "Host",
            Self::Scope => "System/User",
            Self::User => "User",
            Self::Service => "Service",
            Self::Responsibility => "Responsibility",
            Self::Namespace => "Namespace",
            Self::Name => "Name",
            Self::Explanation => "Explanation",
            Self::Facing => "Facing",
            Self::Type => "Type",
            Self::Status => "Status",
        }
    }

    pub fn value(self, row: &Row) -> String {
        let identity = row.identity.as_ref();
        let presentation = row.presentation.as_ref();
        match self {
            Self::Host => identity.map(|value| value.host.clone()).unwrap_or_else(|| {
                row.path
                    .as_deref()
                    .unwrap_or("")
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .into()
            }),
            Self::Scope => identity
                .map(|value| value.scope.clone())
                .unwrap_or_else(|| {
                    if row.path.as_deref().unwrap_or("").contains(".user-") {
                        "user"
                    } else {
                        "system"
                    }
                    .into()
                }),
            Self::User => identity
                .and_then(|value| value.user.clone())
                .unwrap_or_else(|| "(none)".into()),
            Self::Service => identity
                .map(|value| value.service.clone())
                .unwrap_or_else(|| {
                    row.path
                        .as_deref()
                        .unwrap_or("")
                        .split('.')
                        .nth(2)
                        .unwrap_or("")
                        .into()
                }),
            Self::Responsibility => identity
                .map(|value| value.responsibility.clone())
                .unwrap_or_else(|| "main".into()),
            Self::Namespace => identity
                .and_then(|value| value.namespace.clone())
                .unwrap_or_else(|| "(none)".into()),
            Self::Name => identity
                .map(|value| value.name.clone())
                .unwrap_or_else(|| row.name.clone()),
            Self::Explanation => presentation
                .map(|value| value.explanation.clone())
                .or_else(|| row.description.clone())
                .unwrap_or_else(|| "(none)".into()),
            Self::Facing => presentation
                .map(|value| value.facing.clone())
                .unwrap_or_else(|| {
                    if row.external_input_required {
                        "external"
                    } else if row.human_facing {
                        "human"
                    } else {
                        "generated"
                    }
                    .into()
                }),
            Self::Type => presentation
                .map(|value| value.value_type.clone())
                .unwrap_or_else(|| {
                    match row.category {
                        RowCategory::Password => "passphrase",
                        RowCategory::Key => "key",
                        RowCategory::PublicInfo => "public-key",
                        RowCategory::Other | RowCategory::Branch => "value",
                    }
                    .into()
                }),
            Self::Status => if row.is_set { "set" } else { "unset" }.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FacetMode {
    All,
    Whitelist,
    Blacklist,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Facet {
    pub mode: FacetMode,
    pub selected: BTreeSet<String>,
}

impl Default for Facet {
    fn default() -> Self {
        Self {
            mode: FacetMode::All,
            selected: BTreeSet::new(),
        }
    }
}

impl Facet {
    pub fn accepts(&self, value: &str) -> bool {
        match self.mode {
            FacetMode::All => true,
            FacetMode::Whitelist => self.selected.contains(value),
            FacetMode::Blacklist => !self.selected.contains(value),
        }
    }

    pub fn set_mode(&mut self, mode: FacetMode, universe: &BTreeSet<String>) {
        if mode == self.mode {
            return;
        }
        match (self.mode, mode) {
            (FacetMode::All, FacetMode::Whitelist) => self.selected = universe.clone(),
            (FacetMode::All, FacetMode::Blacklist) | (_, FacetMode::All) => self.selected.clear(),
            (FacetMode::Whitelist, FacetMode::Blacklist)
            | (FacetMode::Blacklist, FacetMode::Whitelist) => {
                self.selected = universe.difference(&self.selected).cloned().collect();
            }
            _ => {}
        }
        self.mode = mode;
    }

    pub fn toggle(&mut self, value: &str) {
        if !self.selected.remove(value) {
            self.selected.insert(value.into());
        }
    }
}
