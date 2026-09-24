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

mod types;
pub use types::*;

mod drive;
pub use drive::drive;

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
        (Mode::Browse, UiEvent::Character('f')) => model.cycle_filter(),
        (Mode::Browse, UiEvent::Character('h')) => model.toggle_human(),
        (Mode::Browse, UiEvent::Character('?')) => model.mode = Mode::Help { scroll: 0 },
        (Mode::Help { scroll }, UiEvent::Up) => {
            model.mode = Mode::Help {
                scroll: scroll.saturating_sub(1),
            }
        }
        (Mode::Help { scroll }, UiEvent::Down) => {
            model.mode = Mode::Help {
                scroll: scroll.saturating_add(1),
            }
        }
        (Mode::Help { .. }, UiEvent::Escape | UiEvent::Character('?')) => {}
        (Mode::Help { scroll }, _) => model.mode = Mode::Help { scroll },
        (Mode::Browse, UiEvent::Character('/')) => {
            model.mode = Mode::Search {
                query: model.search.clone(),
            }
        }
        (Mode::Search { mut query }, UiEvent::Character(character)) => {
            query.push(character);
            model.search = query.clone();
            model.selected = 0;
            model.mode = Mode::Search { query };
        }
        (Mode::Search { mut query }, UiEvent::Backspace) => {
            query.pop();
            model.search = query.clone();
            model.selected = 0;
            model.mode = Mode::Search { query };
        }
        (Mode::Search { .. }, UiEvent::Enter) => {}
        (Mode::Search { .. }, UiEvent::Escape) => {
            model.search.clear();
            model.selected = 0;
        }
        (Mode::Search { query }, _) => model.mode = Mode::Search { query },
        (Mode::Browse, UiEvent::Enter) => model.begin_value(Vec::new()),
        (Mode::Browse, UiEvent::Paste(value)) => {
            model.begin_value(value);
            submit_if_edit(model, writer);
        }
        (Mode::Browse, UiEvent::Character('g')) => generated::begin(model, writer),
        (choice @ Mode::GenerateChoice { .. }, event) => {
            return generated::choose(model, writer, choice, event)
        }
        (Mode::Browse, UiEvent::Character('d')) => match model.selected().cloned() {
            Some(row) if row.is_secret() && row.is_set => {
                model.mode = Mode::DeleteConfirm {
                    path: row.path.expect("secret row has path"),
                }
            }
            _ => model.message = Some("select a set secret to delete".into()),
        },
        (Mode::Browse, UiEvent::Character('r')) => match model.selected().cloned() {
            Some(row) if row.is_secret() && row.is_set => {
                let path = row.path.expect("secret row has path");
                match writer.reveal(&path) {
                    Ok(value) => {
                        model.mode = Mode::Reveal {
                            path,
                            value,
                            scroll: 0,
                        }
                    }
                    Err(error) => model.message = Some(error),
                }
            }
            _ => model.message = Some("select a set secret to reveal".into()),
        },
        (Mode::Browse, UiEvent::Character('c')) => match model.selected().cloned() {
            Some(row) if row.is_secret() && row.is_set => {
                let path = row.path.expect("secret row has path");
                model.message = Some(
                    match writer.reveal(&path).and_then(|value| writer.copy(&value)) {
                        Ok(()) => format!("copied {path}"),
                        Err(error) => error,
                    },
                );
            }
            _ => model.message = Some("select a set secret to copy".into()),
        },
        (Mode::Browse, UiEvent::Character('p')) => match model.selected().cloned() {
            Some(row) if row.is_secret() && row.is_set => {
                let path = row.path.expect("secret row has path");
                model.message = Some(match writer.copy_public(&path) {
                    Ok(()) => format!("copied public key for {path}"),
                    Err(error) => error,
                });
            }
            _ => model.message = Some("select a set OpenSSH private key".into()),
        },
        (Mode::DeleteConfirm { path }, UiEvent::Character('y')) => match writer.delete(&path) {
            Ok(()) => model.mark_deleted(&path),
            Err(error) => model.message = Some(error),
        },
        (Mode::DeleteConfirm { .. }, UiEvent::Character('n') | UiEvent::Escape) => {}
        (Mode::DeleteConfirm { path }, _) => model.mode = Mode::DeleteConfirm { path },
        (Mode::Reveal { .. }, UiEvent::Escape | UiEvent::Enter) => {}
        (
            Mode::Reveal {
                path,
                value,
                scroll,
            },
            UiEvent::Up,
        ) => {
            model.mode = Mode::Reveal {
                path,
                value,
                scroll: scroll.saturating_sub(1),
            }
        }
        (
            Mode::Reveal {
                path,
                value,
                scroll,
            },
            UiEvent::Down,
        ) => {
            model.mode = Mode::Reveal {
                path,
                value,
                scroll: scroll.saturating_add(1),
            }
        }
        (
            Mode::Reveal {
                path,
                value,
                scroll,
            },
            UiEvent::Character('c'),
        ) => {
            model.message = Some(match writer.copy(&value) {
                Ok(()) => "value copied".into(),
                Err(error) => error,
            });
            model.mode = Mode::Reveal {
                path,
                value,
                scroll,
            };
        }
        (
            Mode::Reveal {
                path,
                value,
                scroll,
            },
            _,
        ) => {
            model.mode = Mode::Reveal {
                path,
                value,
                scroll,
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
        (Mode::Approval(request), UiEvent::Character('n') | UiEvent::Escape) => {
            match writer.approval(false) {
                Ok(_) => return Action::Rejected,
                Err(message) => {
                    model.message = Some(message);
                    model.mode = Mode::Approval(request);
                }
            }
        }
        (Mode::Approval(request), _) => model.mode = Mode::Approval(request),
        (Mode::Browse, _) => {}
    }
    Action::Continue
}

mod edit;
use edit::{submit, submit_if_edit, submit_if_nonempty, truncate_character};

mod generated;
mod terminal;

pub use terminal::run;
