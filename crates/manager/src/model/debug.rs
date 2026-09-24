use super::*;
use std::fmt;

impl fmt::Debug for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Browse => formatter.write_str("Browse"),
            Self::Help { scroll } => formatter.debug_tuple("Help").field(scroll).finish(),
            Self::Search { query } => formatter.debug_tuple("Search").field(query).finish(),
            Self::DeleteConfirm { path } => {
                formatter.debug_tuple("DeleteConfirm").field(path).finish()
            }
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
            Self::Replace { path, .. } => formatter
                .debug_struct("Replace")
                .field("path", path)
                .field("value", &"<redacted>")
                .finish(),
            Self::GenerateChoice { path, replacing } => formatter
                .debug_struct("GenerateChoice")
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
