//! The Git Commit dialog.
use super::*;
use crate::model::CommitDraft;
use nix_secrets_core::git::{CommitOptions, CommitSummary};

/// Opens the dialog, asking the backend what would be committed.
pub(super) fn open(model: &mut Model, writer: &mut impl SecretWriter) {
    match writer.commit_summary() {
        Ok(summary) => show(model, summary),
        Err(error) => fail_unless_queued(model, error),
    }
}

/// Shows the dialog with a summary, keeping an earlier unsent draft.
pub(super) fn show(model: &mut Model, summary: CommitSummary) {
    let mut draft = model.commit_draft.clone();
    prefill_amend(&mut draft, &summary);
    model.mode = Mode::Commit {
        draft,
        summary,
        editing: false,
    };
}

fn prefill_amend(draft: &mut CommitDraft, summary: &CommitSummary) {
    if draft.amend && draft.message.trim().is_empty() {
        if let Some(message) = &summary.head_message {
            draft.message = message.clone();
        }
    }
}

pub(super) fn reduce(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    mode: Mode,
    event: UiEvent,
) {
    let Mode::Commit {
        mut draft,
        summary,
        editing,
    } = mode
    else {
        unreachable!()
    };
    match event {
        UiEvent::Character(character) => draft.message.push(character),
        UiEvent::Paste(pasted) => draft
            .message
            .push_str(&String::from_utf8_lossy(&pasted).replace("\r\n", "\n")),
        UiEvent::Enter => draft.message.push('\n'),
        UiEvent::Backspace => {
            draft.message.pop();
        }
        UiEvent::Tab => {
            draft.amend = !draft.amend;
            prefill_amend(&mut draft, &summary);
        }
        UiEvent::ToggleSignoff => draft.signoff = !draft.signoff,
        UiEvent::OpenEditor => {
            model.commit_draft = draft.clone();
            model.mode = Mode::Commit {
                draft,
                summary,
                editing: true,
            };
            return;
        }
        UiEvent::Edited(Ok(message)) => draft.message = message,
        UiEvent::Edited(Err(error)) => model.fail(error),
        UiEvent::Escape => {
            // The draft survives for the next time the dialog opens.
            model.commit_draft = draft;
            return;
        }
        UiEvent::Submit => {
            if let Some(problem) = refusal(&draft, &summary) {
                model.fail(problem);
            } else {
                model.commit_draft = draft.clone();
                let options = CommitOptions {
                    message: draft.message.clone(),
                    amend: draft.amend,
                    signoff: draft.signoff,
                };
                match writer.commit(options) {
                    Ok(result) => {
                        committed(model, result);
                        return;
                    }
                    // Queued: the dialog stays until the result arrives.
                    Err(error) if error == OPERATION_QUEUED => {}
                    Err(error) => model.fail(error),
                }
            }
        }
        _ => {}
    }
    model.commit_draft = draft.clone();
    model.mode = Mode::Commit {
        draft,
        summary,
        editing,
    };
}

/// Why the dialog does not send a commit, checked before asking git.
fn refusal(draft: &CommitDraft, summary: &CommitSummary) -> Option<String> {
    if draft.message.trim().is_empty() && !draft.amend {
        return Some("enter a commit message first".into());
    }
    if !summary.foreign_staged.is_empty() {
        return Some(format!(
            "other changes are staged; unstage them first, since only nix-secrets files are committed here: {}",
            summary.foreign_staged.join(", ")
        ));
    }
    None
}

pub(super) fn committed(model: &mut Model, result: nix_secrets_core::git::CommitResult) {
    model.commit_draft = CommitDraft::default();
    if matches!(model.mode, Mode::Commit { .. }) {
        model.mode = Mode::Browse;
    }
    model.inform(format!("committed {}\n{}", result.hash, result.output));
}

/// Applies a mouse click on one of the dialog's controls.
pub(super) fn click(
    model: &mut Model,
    target: MouseTarget,
    writer: &mut impl SecretWriter,
) -> Action {
    let event = match target {
        MouseTarget::CommitAmend => UiEvent::Tab,
        MouseTarget::CommitSignoff => UiEvent::ToggleSignoff,
        MouseTarget::CommitEditor => UiEvent::OpenEditor,
        MouseTarget::CommitSubmit => UiEvent::Submit,
        _ => return Action::Continue,
    };
    super::reduce(model, event, writer)
}
