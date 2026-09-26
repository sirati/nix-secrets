//! The secret-request modal. It sits above every other dialog and notice;
//! the dialog underneath keeps its state and is usable again once the
//! request is answered.
//!
//! Only Ctrl+Shift+Y or the Yes button approves. n, Esc and Enter deny.
//! After [`crate::operator_channel::DECISION_TIMEOUT`] the channel denies
//! on its own and the modal closes.
use super::*;
use crate::operator_channel::SecretPrompt;
use std::time::Instant;

/// Handles input while a request is shown. Returns whether it consumed the
/// event; if not, no request is open and the event goes on as usual.
pub(super) fn intercept(
    model: &mut Model,
    event: &UiEvent,
    writer: &mut impl SecretWriter,
) -> bool {
    let Some(prompt) = &model.secret_prompt else {
        return false;
    };
    let decision = match event {
        UiEvent::Hover(target) => {
            model.hover = *target;
            return true;
        }
        UiEvent::Approval(request) => {
            model.offer_approval(request.clone());
            return true;
        }
        UiEvent::Up => {
            model.secret_scroll = model.scrolled(model.secret_scroll, false);
            return true;
        }
        UiEvent::Down => {
            model.secret_scroll = model.scrolled(model.secret_scroll, true);
            return true;
        }
        UiEvent::ConfirmLoss | UiEvent::Click(MouseTarget::ConfirmLoss) => true,
        UiEvent::Character('n')
        | UiEvent::Escape
        | UiEvent::Enter
        | UiEvent::Click(MouseTarget::Shortcut(
            Shortcut::Escape | Shortcut::Enter | Shortcut::Character('n'),
        )) => false,
        // Everything else is swallowed: no key reaches the dialog below.
        _ => return true,
    };
    let id = prompt.id.clone();
    let count = prompt.values.len();
    model.secret_prompt = None;
    model.secret_scroll = 0;
    // An approval shows the progress strip; the outcome arrives as a notice.
    if let Err(error) = writer.answer_secret(&id, decision, count) {
        model.fail(error);
    }
    true
}

/// Shows a new request, or closes one whose time ran out.
pub(super) fn tick(model: &mut Model, writer: &mut impl SecretWriter) -> bool {
    let mut changed = false;
    if let Some(prompt) = writer.poll_secret_prompt() {
        model.secret_prompt = Some(prompt);
        model.secret_scroll = 0;
        changed = true;
    }
    if model
        .secret_prompt
        .as_ref()
        .is_some_and(|prompt| Instant::now() >= prompt.deadline)
    {
        // The channel denies at the same deadline and reports it.
        model.secret_prompt = None;
        changed = true;
    }
    // The countdown moves.
    changed || model.secret_prompt.is_some()
}

pub(super) fn finished(model: &mut Model, requester: String, result: Result<usize, String>) {
    match result {
        Ok(count) => model.inform(format!(
            "Sent {count} secret value{} to {requester}.",
            if count == 1 { "" } else { "s" }
        )),
        Err(reason) => {
            model.secret_prompt = None;
            model.fail(format!("Secret request from {requester} failed: {reason}"))
        }
    }
}

fn process_lines(label: &str, process: &crate::model::ProcessDisplay<'_>) -> String {
    let info = process.0;
    let mut text = format!("{label}: PID {}", info.pid);
    if let Some(executable) = &info.executable {
        text.push_str(&format!(", {executable}"));
    }
    if !info.argv.is_empty() {
        text.push_str(&format!("\n  command: {}", info.argv.join(" ")));
    }
    if let Some(cwd) = &info.cwd {
        text.push_str(&format!("\n  cwd: {cwd}"));
    }
    text
}

/// The modal body.
pub(super) fn body(prompt: &SecretPrompt) -> String {
    let remaining = prompt.deadline.saturating_duration_since(Instant::now());
    let mut text = format!(
        "A process on the backend host asks for {} secret value{}.\n\n",
        prompt.values.len(),
        if prompt.values.len() == 1 { "" } else { "s" }
    );
    if let Some(parent) = &prompt.parent {
        text.push_str(&process_lines(
            "Program",
            &crate::model::ProcessDisplay(parent),
        ));
        text.push('\n');
    }
    text.push_str(&process_lines(
        "Requester",
        &crate::model::ProcessDisplay(&prompt.requester),
    ));
    text.push_str("\n\nValues:\n");
    for value in &prompt.values {
        text.push_str(&format!("• {} ({})\n", value.identifier, value.kind));
        if let Some(description) = &value.description {
            text.push_str(&format!("  {description}\n"));
        }
        for recipient in &value.recipients {
            text.push_str(&format!("  recipient {recipient}\n"));
        }
    }
    text.push_str(&format!(
        "\nDecrypted with: {}\nThe values are sent to the backend, which hands them only to this program until it exits.\n\nDenies automatically in {} s.\nCtrl+Shift+Y or Yes: send · n, Enter or Esc: deny",
        prompt.identity,
        remaining.as_secs()
    ));
    text
}
