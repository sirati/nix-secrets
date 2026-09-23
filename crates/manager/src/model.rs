use crate::tree::{Row, RowCategory};
use std::fmt;
use std::time::Instant;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequest {
    pub id: String,
    pub target: String,
    pub create: Vec<String>,
    pub replace: Vec<String>,
    pub recipient_keys: Vec<String>,
    pub host_key: Option<String>,
    pub tasks: Vec<TaskApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskApproval {
    pub identifier: String,
    pub input_is_set: bool,
    pub output_is_set: Option<bool>,
    pub requires_input: bool,
}

#[derive(Eq, PartialEq)]
pub enum Mode {
    Browse,
    Help {
        scroll: u16,
    },
    Search {
        query: String,
    },
    DeleteConfirm {
        path: String,
    },
    Reveal {
        path: String,
        value: Zeroizing<Vec<u8>>,
        scroll: u16,
    },
    Edit {
        path: String,
        value: Zeroizing<Vec<u8>>,
    },
    Replace {
        path: String,
        value: Zeroizing<Vec<u8>>,
    },
    GenerateChoice {
        path: String,
        replacing: bool,
    },
    GeneratedPreview {
        path: String,
        value: Zeroizing<Vec<u8>>,
        revealed: bool,
        replacing: bool,
    },
    Approval(ApprovalRequest),
    ProviderFailure {
        message: String,
        path: String,
        value: Zeroizing<Vec<u8>>,
    },
}

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

pub struct Model {
    pub rows: Vec<Row>,
    pub selected: usize,
    pub mode: Mode,
    pub message: Option<String>,
    pub message_since: Option<Instant>,
    pub filter: ViewFilter,
    pub human_only: bool,
    pub search: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewFilter {
    All,
    Keys,
    Passwords,
    PublicInfo,
}

impl ViewFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Keys,
            Self::Keys => Self::Passwords,
            Self::Passwords => Self::PublicInfo,
            Self::PublicInfo => Self::All,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Keys => "keys",
            Self::Passwords => "passwords",
            Self::PublicInfo => "public info",
        }
    }
}

impl Model {
    pub fn update_rows(&mut self, rows: Vec<Row>) {
        let selected_path = self.selected().and_then(|row| row.path.clone());
        self.rows = rows;
        if let Some(path) = selected_path {
            self.selected = self
                .visible_rows()
                .iter()
                .position(|index| self.rows[*index].path.as_deref() == Some(path.as_str()))
                .unwrap_or(0);
        } else {
            self.selected = self
                .selected
                .min(self.visible_rows().len().saturating_sub(1));
        }
    }
    pub fn new(rows: Vec<Row>) -> Self {
        Self {
            rows,
            selected: 0,
            mode: Mode::Browse,
            message: None,
            message_since: None,
            filter: ViewFilter::All,
            human_only: false,
            search: String::new(),
        }
    }

    pub fn selected(&self) -> Option<&Row> {
        self.visible_rows()
            .get(self.selected)
            .and_then(|index| self.rows.get(*index))
    }

    pub fn visible_rows(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter_map(|(index, row)| {
                let visible = match self.filter {
                    ViewFilter::All => true,
                    ViewFilter::Keys => row.category == RowCategory::Key,
                    ViewFilter::Passwords => row.category == RowCategory::Password,
                    ViewFilter::PublicInfo => row.category == RowCategory::PublicInfo,
                };
                let human_visible = !self.human_only || row.human_facing;
                let needle = self.search.to_ascii_lowercase();
                let searchable = format!(
                    "{} {} {}",
                    row.name,
                    row.path.as_deref().unwrap_or(""),
                    row.description.as_deref().unwrap_or("")
                )
                .to_ascii_lowercase();
                (visible && human_visible && searchable.contains(&needle)).then_some(index)
            })
            .collect()
    }

    pub fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.selected = 0;
        self.message = Some(format!("showing {}", self.filter.name()));
    }

    pub fn toggle_human(&mut self) {
        self.human_only = !self.human_only;
        self.selected = 0;
        self.message = Some(
            if self.human_only {
                "showing human-facing items"
            } else {
                "showing all audiences"
            }
            .into(),
        );
    }

    pub fn move_by(&mut self, amount: isize) {
        let count = self.visible_rows().len();
        if count == 0 {
            return;
        }
        self.selected = self.selected.saturating_add_signed(amount).min(count - 1);
    }

    pub fn begin_value(&mut self, value: Vec<u8>) {
        let Some(row) = self.selected().filter(|row| row.is_secret()) else {
            return;
        };
        let path = row.path.clone().expect("secret row has path");
        let value = Zeroizing::new(value);
        self.mode = if row.is_set {
            Mode::Replace { path, value }
        } else {
            Mode::Edit { path, value }
        };
    }

    pub fn mark_saved(&mut self, path: &str) {
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|row| row.path.as_deref() == Some(path))
        {
            row.is_set = true;
        }
        self.mode = Mode::Browse;
        self.message = Some(format!("saved {path}"));
    }

    pub fn mark_deleted(&mut self, path: &str) {
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|row| row.path.as_deref() == Some(path))
        {
            row.is_set = false;
        }
        self.mode = Mode::Browse;
        self.message = Some(format!("deleted {path}"));
    }

    pub fn apply_task_status(&mut self, request: &ApprovalRequest) {
        for task in &request.tasks {
            if let Some(row) = self
                .rows
                .iter_mut()
                .find(|row| row.path.as_deref() == Some(&task.identifier))
            {
                row.is_set = task.input_is_set;
                row.output_is_set = task.output_is_set;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(set: bool) -> Row {
        Row {
            depth: 0,
            name: "key".into(),
            path: Some("h.services.s.key".into()),
            is_set: set,
            is_task: false,
            can_generate: false,
            output_is_set: None,
            description: None,
            category: RowCategory::Other,
            human_facing: false,
        }
    }

    #[test]
    fn replacing_a_set_leaf_requires_confirmation() {
        let mut model = Model::new(vec![leaf(true)]);
        model.begin_value(b"new".to_vec());
        assert!(matches!(model.mode, Mode::Replace { .. }));
    }

    #[test]
    fn unset_leaf_enters_editor_directly() {
        let mut model = Model::new(vec![leaf(false)]);
        model.begin_value(Vec::new());
        assert!(matches!(model.mode, Mode::Edit { .. }));
    }
}
