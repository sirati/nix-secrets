use crate::tree::{Row, RowCategory};
use std::collections::VecDeque;
use zeroize::Zeroizing;

mod visibility;

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
    BulkGenerateConfirm {
        paths: Vec<String>,
    },
    BulkProgress {
        total: usize,
        done: usize,
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

mod debug;

pub struct Model {
    pub rows: Vec<Row>,
    pub selected: usize,
    pub mode: Mode,
    pub message: Option<String>,
    pub modal_scroll: u16,
    pub hover: Option<crate::ui::MouseTarget>,
    pub notifications: VecDeque<String>,
    pub pending_approvals: VecDeque<ApprovalRequest>,
    pub pending_dialogs: VecDeque<Mode>,
    pub filter: ViewFilter,
    pub human_only: bool,
    pub search: String,
}

pub struct VisibleRow {
    pub index: usize,
    pub depth: usize,
    pub label: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewFilter {
    Required,
    All,
    Keys,
    Passwords,
    PublicInfo,
}

impl ViewFilter {
    pub fn next(self) -> Self {
        match self {
            Self::Required => Self::All,
            Self::All => Self::Keys,
            Self::Keys => Self::Passwords,
            Self::Passwords => Self::PublicInfo,
            Self::PublicInfo => Self::Required,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Required => "operator input",
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
            modal_scroll: 0,
            hover: None,
            notifications: VecDeque::new(),
            pending_approvals: VecDeque::new(),
            pending_dialogs: VecDeque::new(),
            filter: ViewFilter::Required,
            human_only: false,
            search: String::new(),
        }
    }

    pub fn selected(&self) -> Option<&Row> {
        self.visible_rows()
            .get(self.selected)
            .and_then(|index| self.rows.get(*index))
    }

    pub fn notify(&mut self, message: impl Into<String>) {
        let message = message.into();
        if self.message.as_deref() == Some(message.as_str())
            || self
                .notifications
                .back()
                .is_some_and(|queued| queued == &message)
        {
            return;
        }
        if self.message.is_none() {
            self.message = Some(message);
        } else {
            self.notifications.push_back(message);
        }
    }

    pub fn acknowledge(&mut self) {
        self.message = self.notifications.pop_front();
        self.modal_scroll = 0;
        self.show_pending_approval();
    }

    pub fn offer_approval(&mut self, request: ApprovalRequest) {
        self.apply_task_status(&request);
        self.pending_approvals.push_back(request);
        self.show_pending_approval();
    }

    pub fn show_pending_approval(&mut self) {
        if self.message.is_none() && matches!(self.mode, Mode::Browse) {
            if let Some(dialog) = self.pending_dialogs.pop_front() {
                self.mode = dialog;
            } else if let Some(request) = self.pending_approvals.pop_front() {
                self.mode = Mode::Approval(request);
            }
        }
    }

    pub fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.selected = 0;
    }
    pub fn set_filter(&mut self, filter: ViewFilter) {
        self.filter = filter;
        self.selected = 0;
    }

    pub fn set_human_only(&mut self, enabled: bool) {
        self.human_only = enabled;
        self.selected = 0;
    }

    pub fn toggle_human(&mut self) {
        self.human_only = !self.human_only;
        self.selected = 0;
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
        self.notify(format!("saved {path}"));
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
        self.notify(format!("deleted {path}"));
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
mod tests;
