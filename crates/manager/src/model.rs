use crate::tree::Row;
use std::fmt;
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
}

#[derive(Eq, PartialEq)]
pub enum Mode {
    Browse,
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
}

impl Model {
    pub fn new(rows: Vec<Row>) -> Self {
        Self {
            rows,
            selected: 0,
            mode: Mode::Browse,
            message: None,
        }
    }

    pub fn selected(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    pub fn move_by(&mut self, amount: isize) {
        if self.rows.is_empty() {
            return;
        }
        self.selected = self
            .selected
            .saturating_add_signed(amount)
            .min(self.rows.len() - 1);
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
