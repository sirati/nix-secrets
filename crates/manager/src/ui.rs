use crate::model::{ApprovalRequest, Mode, Model};
use crate::tree::Row;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{self, Stdout};
use zeroize::Zeroizing;

#[derive(Debug, Eq, PartialEq)]
pub enum UiEvent {
    Up,
    Down,
    Enter,
    Escape,
    Character(char),
    Backspace,
    Paste(Vec<u8>),
    Approval(ApprovalRequest),
    Tick,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Action {
    Continue,
    Quit,
    Saved(String),
    Approved,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerateKind {
    Password,
    Passphrase,
}

pub trait SecretWriter {
    fn write(
        &mut self,
        path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)>;
    fn poll_approval(&mut self) -> Result<Option<ApprovalRequest>, String> {
        Ok(None)
    }
    fn approval(&mut self, _accepted: bool) -> Result<Option<ApprovalRequest>, String> {
        Ok(None)
    }
    fn request_deployment(&mut self, _path: &str) -> Result<(), String> {
        Ok(())
    }
    fn generate(&mut self, _path: &str, _kind: GenerateKind) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("select a password leaf".into())
    }
    fn copy(&mut self, _value: &[u8]) -> Result<(), String> {
        Err("no clipboard provider is available".into())
    }
}

pub trait Frontend {
    fn draw(&mut self, model: &Model) -> io::Result<()>;
    fn read(&mut self) -> io::Result<UiEvent>;
}

pub fn drive(
    frontend: &mut impl Frontend,
    writer: &mut impl SecretWriter,
    model: &mut Model,
) -> io::Result<()> {
    loop {
        frontend.draw(model)?;
        let event = frontend.read()?;
        if event == UiEvent::Tick {
            match writer.poll_approval() {
                Ok(Some(request)) => {
                    model.apply_task_status(&request);
                    model.mode = Mode::Approval(request);
                }
                Ok(None) => {}
                Err(message) => {
                    model.mode = Mode::Browse;
                    model.message = Some(message);
                }
            }
            continue;
        }
        if reduce(model, event, writer) == Action::Quit {
            return Ok(());
        }
    }
}

pub fn reduce(model: &mut Model, event: UiEvent, writer: &mut impl SecretWriter) -> Action {
    if let UiEvent::Approval(request) = event {
        model.apply_task_status(&request);
        model.mode = Mode::Approval(request);
        return Action::Continue;
    }
    let mode = std::mem::replace(&mut model.mode, Mode::Browse);
    match (mode, event) {
        (Mode::Browse, UiEvent::Up) => model.move_by(-1),
        (Mode::Browse, UiEvent::Down) => model.move_by(1),
        (Mode::Browse, UiEvent::Enter) => model.begin_value(Vec::new()),
        (Mode::Browse, UiEvent::Paste(value)) => {
            model.begin_value(value);
            submit_if_edit(model, writer);
        }
        (Mode::Browse, UiEvent::Character('g')) => generated::begin(model, writer),
        (choice @ Mode::GenerateChoice { .. }, event) => {
            return generated::choose(model, writer, choice, event)
        }
        (Mode::Browse, UiEvent::Character('d')) => {
            let selected = model.selected().cloned();
            match selected {
                Some(row) if row.is_secret() && row.is_set => {
                    let path = row.path.expect("secret row has path");
                    model.message = Some(match writer.request_deployment(&path) {
                        Ok(()) => format!("deployment requested for {path}"),
                        Err(error) => error,
                    });
                }
                Some(row) if row.is_task() => model.message = Some("task input is unset".into()),
                Some(row) if row.is_secret() => model.message = Some("secret is unset".into()),
                _ => model.message = Some("select a set secret to deploy".into()),
            }
        }
        (Mode::Browse, UiEvent::Escape) => return Action::Quit,
        (Mode::Edit { path, mut value }, UiEvent::Character(character)) => {
            let mut bytes = [0; 4];
            value.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
            model.mode = Mode::Edit { path, value };
        }
        (Mode::Edit { path, mut value }, UiEvent::Backspace) => {
            truncate_character(&mut value);
            model.mode = Mode::Edit { path, value };
        }
        (Mode::Edit { path, value }, UiEvent::Enter) => submit(model, writer, path, value),
        (Mode::Edit { .. }, UiEvent::Escape) => {}
        (Mode::Edit { path, value }, _) => model.mode = Mode::Edit { path, value },
        (Mode::Replace { path, value }, UiEvent::Character('y')) => {
            model.mode = Mode::Edit { path, value };
            submit_if_nonempty(model, writer);
        }
        (Mode::Replace { .. }, UiEvent::Character('n') | UiEvent::Escape) => {}
        (Mode::Replace { path, value }, _) => model.mode = Mode::Replace { path, value },
        (preview @ Mode::GeneratedPreview { .. }, event) => {
            return generated::reduce(model, writer, preview, event)
        }
        (Mode::ProviderFailure { path, value, .. }, UiEvent::Character('r')) => {
            submit(model, writer, path, value);
        }
        (Mode::ProviderFailure { .. }, UiEvent::Escape) => {}
        (
            Mode::ProviderFailure {
                message,
                path,
                value,
            },
            _,
        ) => {
            model.mode = Mode::ProviderFailure {
                message,
                path,
                value,
            };
        }
        (Mode::Approval(request), UiEvent::Character('y')) => match writer.approval(true) {
            Ok(Some(next)) => model.mode = Mode::Approval(next),
            Ok(None) => return Action::Approved,
            Err(message) => {
                model.message = Some(message);
                model.mode = Mode::Approval(request);
            }
        },
        (Mode::Approval(_), UiEvent::Character('n') | UiEvent::Escape) => {
            if let Err(message) = writer.approval(false) {
                model.message = Some(message);
            }
            return Action::Rejected;
        }
        (Mode::Approval(request), _) => model.mode = Mode::Approval(request),
        (Mode::Browse, _) => {}
    }
    Action::Continue
}

fn submit_if_edit(model: &mut Model, writer: &mut impl SecretWriter) {
    let mode = std::mem::replace(&mut model.mode, Mode::Browse);
    if let Mode::Edit { path, value } = mode {
        submit(model, writer, path, value);
    } else {
        model.mode = mode;
    }
}

fn submit_if_nonempty(model: &mut Model, writer: &mut impl SecretWriter) {
    let mode = std::mem::replace(&mut model.mode, Mode::Browse);
    if let Mode::Edit { path, value } = mode {
        if value.is_empty() {
            model.mode = Mode::Edit { path, value };
        } else {
            submit(model, writer, path, value);
        }
    } else {
        model.mode = mode;
    }
}

fn submit(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    path: String,
    value: Zeroizing<Vec<u8>>,
) {
    match writer.write(&path, value) {
        Ok(Action::Saved(saved)) => model.mark_saved(&saved),
        Ok(_) => model.mode = Mode::Browse,
        Err((message, value)) => {
            model.mode = Mode::ProviderFailure {
                message,
                path,
                value,
            }
        }
    }
}

fn truncate_character(value: &mut Vec<u8>) {
    if let Ok(text) = std::str::from_utf8(value) {
        if let Some((index, _)) = text.char_indices().next_back() {
            value.truncate(index);
        }
    } else {
        value.pop();
    }
}

mod generated;
mod terminal;

pub use terminal::run;
