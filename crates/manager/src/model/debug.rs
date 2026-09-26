use super::*;
use std::fmt;

impl fmt::Debug for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Browse => formatter.write_str("Browse"),
            Self::Properties { scroll } => {
                formatter.debug_tuple("Properties").field(scroll).finish()
            }
            Self::FacetCategories { selected } => formatter
                .debug_tuple("FacetCategories")
                .field(selected)
                .finish(),
            Self::FacetValues {
                attribute,
                selected,
            } => formatter
                .debug_tuple("FacetValues")
                .field(attribute)
                .field(selected)
                .finish(),
            Self::FacetFirstChoice { attribute, value } => formatter
                .debug_tuple("FacetFirstChoice")
                .field(attribute)
                .field(value)
                .finish(),
            Self::TreeOrder { selected } => {
                formatter.debug_tuple("TreeOrder").field(selected).finish()
            }
            Self::Profiles { selected } => {
                formatter.debug_tuple("Profiles").field(selected).finish()
            }
            Self::ProfileSave { name } => formatter.debug_tuple("ProfileSave").field(name).finish(),
            Self::ProfileOverwrite { name } => formatter
                .debug_tuple("ProfileOverwrite")
                .field(name)
                .finish(),
            Self::ProfileDelete { name } => {
                formatter.debug_tuple("ProfileDelete").field(name).finish()
            }
            Self::Help { scroll } => formatter.debug_tuple("Help").field(scroll).finish(),
            Self::Settings { selected } => {
                formatter.debug_tuple("Settings").field(selected).finish()
            }
            Self::Search { query } => formatter.debug_tuple("Search").field(query).finish(),
            Self::DeleteConfirm { path, commit } => formatter
                .debug_struct("DeleteConfirm")
                .field("path", path)
                .field("commit", commit)
                .finish(),
            Self::Reveal { path, .. } => formatter
                .debug_struct("Reveal")
                .field("path", path)
                .field("value", &"<redacted>")
                .finish(),
            Self::Edit { path, .. } => formatter
                .debug_struct("Edit")
                .field("path", path)
                .field("value", &"<redacted>")
                .finish(),
            Self::Commit { draft, editing, .. } => formatter
                .debug_struct("Commit")
                .field("draft", draft)
                .field("editing", editing)
                .finish(),
            Self::Replace { path, commit, .. } => formatter
                .debug_struct("Replace")
                .field("path", path)
                .field("value", &"<redacted>")
                .field("commit", commit)
                .finish(),
            Self::GenerateChoice { path, replacing } => formatter
                .debug_struct("GenerateChoice")
                .field("path", path)
                .field("replacing", replacing)
                .finish(),
            Self::KeypairConfirm { path, replacing } => formatter
                .debug_struct("KeypairConfirm")
                .field("path", path)
                .field("replacing", replacing)
                .finish(),
            Self::BulkGenerateConfirm { paths } => formatter
                .debug_struct("BulkGenerateConfirm")
                .field("count", &paths.len())
                .finish(),
            Self::BulkProgress { total, done } => formatter
                .debug_struct("BulkProgress")
                .field("total", total)
                .field("done", done)
                .finish(),
            Self::GeneratedPreview {
                path,
                revealed,
                replacing,
                ..
            } => formatter
                .debug_struct("GeneratedPreview")
                .field("path", path)
                .field("value", &"<redacted>")
                .field("revealed", revealed)
                .field("replacing", replacing)
                .finish(),
            Self::Approval(request) => formatter.debug_tuple("Approval").field(request).finish(),
            Self::ProviderFailure { message, path, .. } => formatter
                .debug_struct("ProviderFailure")
                .field("message", message)
                .field("path", path)
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}
