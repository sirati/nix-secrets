use crate::model::{ApprovalRequest, Mode, Model};
use crate::tree::Row;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};
use std::io;
use zeroize::Zeroizing;

fn fail_unless_queued(model: &mut Model, error: String) {
    // Completion will deliver the actual result without interrupting input.
    if error != OPERATION_QUEUED {
        model.fail(error);
    }
}

fn report(model: &mut Model, result: Result<String, String>) {
    match result {
        Ok(message) => model.inform(message),
        Err(error) => fail_unless_queued(model, error),
    }
}

mod types;
pub use types::*;

mod drive;
#[cfg(test)]
pub(crate) use drive::apply_completion_for_tests;
pub use drive::drive;

mod reducer;
pub use reducer::reduce;
mod approval;
mod provider_failure;

mod edit;
use edit::{submit, submit_entry, submit_if_edit, truncate_character};

mod facets;
mod generated;
mod mouse;
mod prelude;
mod profiles;
mod terminal;

pub use terminal::run;
