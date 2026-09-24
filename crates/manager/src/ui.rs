use crate::model::{ApprovalRequest, Mode, Model};
use crate::tree::Row;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{self, Stdout};
use zeroize::Zeroizing;

fn notify_operation_result(model: &mut Model, error: String) {
    // Completion will deliver the actual result without interrupting input.
    if error != OPERATION_QUEUED {
        model.notify(error);
    }
}

mod types;
pub use types::*;

mod drive;
pub use drive::drive;

mod reducer;
pub use reducer::reduce;
mod approval;
mod provider_failure;

mod edit;
use edit::{submit, submit_if_edit, submit_if_nonempty, truncate_character};

mod generated;
mod terminal;

pub use terminal::run;
