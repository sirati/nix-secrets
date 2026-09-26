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
    pub fn key(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Scope => "scope",
            Self::User => "user",
            Self::Service => "service",
            Self::Responsibility => "responsibility",
            Self::Namespace => "namespace",
            Self::Name => "name",
            Self::Explanation => "explanation",
            Self::Facing => "facing",
            Self::Type => "type",
            Self::Status => "status",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|attribute| attribute.key() == key)
    }
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

    /// Attributes that can form tree levels and filter facets. Explanation is
    /// free text: it stays searchable and in the properties view only.
    pub const GROUPING: [Self; 10] = [
        Self::Host,
        Self::Scope,
        Self::User,
        Self::Service,
        Self::Responsibility,
        Self::Namespace,
        Self::Name,
        Self::Facing,
        Self::Type,
        Self::Status,
    ];

    pub fn groups(self) -> bool {
        Self::GROUPING.contains(&self)
    }

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

    /// The attribute's value for a row, or `None` when it does not apply, such
    /// as the user of a system service. Inapplicable attributes add no tree
    /// level, crumb, facet value, or properties line.
    pub fn value(self, row: &Row) -> Option<String> {
        self.raw_value(row)
            .filter(|value| !value.is_empty() && value != "(none)")
    }

    fn raw_value(self, row: &Row) -> Option<String> {
        let identity = row.identity.as_ref();
        let presentation = row.presentation.as_ref();
        Some(match self {
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
            Self::User => return identity.and_then(|value| value.user.clone()),
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
            Self::Namespace => return identity.and_then(|value| value.namespace.clone()),
            Self::Name => identity
                .map(|value| value.name.clone())
                .unwrap_or_else(|| row.name.clone()),
            Self::Explanation => {
                return presentation
                    .map(|value| value.explanation.clone())
                    .or_else(|| row.description.clone())
            }
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
                        RowCategory::Operator => "operator-key",
                        RowCategory::Other | RowCategory::Branch => "value",
                    }
                    .into()
                }),
            Self::Status => if row.is_set { "set" } else { "unset" }.into(),
        })
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
