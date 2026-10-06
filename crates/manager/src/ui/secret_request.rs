//! The secret-request modal. It belongs to a procedure (see
//! [`crate::model::Procedure`]) and is on screen while that procedure is in
//! the foreground; the dialog underneath keeps its state and is usable
//! again once the request is answered or minimised.
//!
//! Only Ctrl+Shift+Y or the Yes button approves. n, Esc and Enter deny; d
//! toggles the details; m minimises the procedure to the task bar and M
//! restores the next waiting one. A request outside a procedure, or the
//! first step of one, denies itself after
//! [`crate::operator_channel::DECISION_TIMEOUT`] unless c cancels that.
use super::*;
use crate::operator_channel::SecretPrompt;
use nix_secrets_core::secret_request::ProcessInfo;
use std::path::Path;
use std::time::Instant;
use unicode_width::UnicodeWidthStr;

/// Restores a task bar entry, or explains why it cannot.
pub(super) fn restore(model: &mut Model, index: usize) {
    let Some(id) = model.procedures.get(index).map(|procedure| procedure.id.clone()) else {
        return;
    };
    if let Err(reason) = model.restore(&id) {
        model.inform(reason);
    }
}

/// Handles input while a request is shown. Returns whether it consumed the
/// event; if not, no request is open and the event goes on as usual.
pub(super) fn intercept(
    model: &mut Model,
    event: &UiEvent,
    writer: &mut impl SecretWriter,
) -> bool {
    let Some(prompt) = model.shown_prompt() else {
        return between(model, event);
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
        UiEvent::Character('d')
        | UiEvent::Click(MouseTarget::Shortcut(Shortcut::Character('d'))) => {
            model.secret_details = !model.secret_details;
            model.secret_scroll = 0;
            return true;
        }
        UiEvent::Character('m')
        | UiEvent::Click(MouseTarget::Shortcut(Shortcut::Character('m'))) => {
            model.minimise();
            return true;
        }
        UiEvent::Character('M') => {
            if let Err(reason) = model.restore_next() {
                model.inform(reason);
            }
            return true;
        }
        UiEvent::Click(MouseTarget::Procedure(index)) => {
            restore(model, *index);
            return true;
        }
        UiEvent::Character('c')
        | UiEvent::Click(MouseTarget::Shortcut(Shortcut::Character('c'))) => {
            if let Some(id) = model.cancel_countdown() {
                if let Err(error) = writer.cancel_countdown(&id) {
                    model.fail(error);
                }
            }
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
    // SSH authentication returns a signature and zero secret values.
    let count = if prompt.ssh_signature || prompt.artifact_signature || prompt.closure_signature {
        0
    } else {
        prompt.values.len()
    };
    let prompt = model.take_shown_prompt().expect("a prompt is shown");
    // An approval shows the progress strip; the outcome arrives in the
    // procedure's dialog, or as a notice for a request of its own.
    if let Err(error) = writer.answer_secret(&prompt.id, decision, count) {
        model.fail(error);
    }
    true
}

/// Handles input while a procedure dialog shows what happens between its
/// prompts. While the procedure works, m or Esc minimises it and other keys
/// do nothing. Any key closes a successful result; a failure closes only with
/// Enter or OK. Returns whether it consumed the event.
fn between(model: &mut Model, event: &UiEvent) -> bool {
    // A notice drawn above the dialog takes the keys first.
    if model.message.is_some() {
        return false;
    }
    let Some(procedure) = model.between_shown() else {
        return false;
    };
    let result = match &procedure.between {
        Some(crate::model::Between::Result { succeeded, .. }) => Some(*succeeded),
        _ => None,
    };
    match event {
        UiEvent::Refresh | UiEvent::Tick => return false,
        UiEvent::Hover(target) => model.hover = *target,
        UiEvent::Approval(request) => model.offer_approval(request.clone()),
        UiEvent::Click(MouseTarget::Procedure(index)) => restore(model, *index),
        UiEvent::Character('M') => {
            let seen = result == Some(true);
            if seen {
                model.dismiss_result();
            }
            if let Err(reason) = model.restore_next() {
                if !seen {
                    model.inform(reason);
                }
            }
        }
        UiEvent::Character('m')
        | UiEvent::Click(MouseTarget::Shortcut(Shortcut::Character('m'))) => {
            model.minimise();
        }
        UiEvent::Escape if result.is_none() => {
            model.minimise();
        }
        UiEvent::Enter | UiEvent::Click(MouseTarget::Shortcut(Shortcut::Enter))
            if result == Some(false) =>
        {
            model.dismiss_result()
        }
        _ if result == Some(true) => model.dismiss_result(),
        _ => {}
    }
    true
}

/// Takes in new requests and procedure news, closes requests whose time
/// ran out and moves the flashing. Returns whether to redraw.
pub(super) fn tick(model: &mut Model, writer: &mut impl SecretWriter) -> bool {
    let mut changed = false;
    while let Some(event) = writer.poll_procedure_event() {
        match event {
            ProcedureEvent::Step(step) => model.procedure_step(step),
            ProcedureEvent::Ended(id, exit_code) => model.procedure_ended(&id, exit_code),
            ProcedureEvent::Withdrawn(id) => {
                model.remove_prompt(&id);
            }
            ProcedureEvent::Disconnected => model.connection_lost(),
            ProcedureEvent::Reconnected => {
                model.inform("Reconnected to the backend. Requests that still wait are shown again from the start.")
            }
            ProcedureEvent::Synced(ids) => model.procedures_synced(&ids),
        }
        changed = true;
    }
    while let Some(prompt) = writer.poll_secret_prompt() {
        model.offer_prompt(prompt);
        changed = true;
    }
    let now = Instant::now();
    // The channel denies at the same deadline and reports it.
    changed |= model.expire_prompts(now);
    changed |= model.flash_tick(now);
    // A waiting procedure dialog's spinner moves on a timer, never faster.
    changed |= model.spinner_tick(now);
    if changed {
        model.show_pending_approval();
    }
    // Countdowns move, in the dialog and in the task bar.
    changed
        || model
            .procedures
            .iter()
            .any(|procedure| procedure.prompts.iter().any(|prompt| prompt.deadline.is_some()))
}

pub(super) fn finished(
    model: &mut Model,
    id: &str,
    requester: String,
    result: Result<usize, String>,
) {
    match result {
        Ok(count) => model.inform(format!(
            "Sent {count} secret value{} to {requester}.",
            if count == 1 { "" } else { "s" }
        )),
        Err(reason) => {
            model.remove_prompt(id);
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

/// The file name of a process's executable, else of its first argument.
fn program_name(process: &ProcessInfo) -> String {
    process
        .executable
        .as_deref()
        .or(process.argv.first().map(String::as_str))
        .map(|path| {
            Path::new(path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_owned())
        })
        .unwrap_or_else(|| "unknown program".into())
}

/// The modal title: who asked.
pub(crate) fn title(prompt: &SecretPrompt) -> String {
    format!(
        "{} from {} (pid {})",
        if prompt.closure_signature {
            "Closure signing request"
        } else if prompt.artifact_signature {
            "Artifact signing request"
        } else if prompt.ssh_signature {
            "SSH authentication request"
        } else {
            "Secret request"
        },
        program_name(&prompt.requester),
        prompt.requester.pid
    )
}

/// The dialog title: the procedure and its step, or for a request of its
/// own, who asked.
pub(crate) fn dialog_title(prompt: &SecretPrompt) -> String {
    match &prompt.procedure {
        Some(step) => format!("{} · {}: {}", step.title, step.position(), step.label),
        None => title(prompt),
    }
}

/// Where the private key comes from, in one word.
fn key_source(identity: &str) -> &str {
    if identity.starts_with("1Password") {
        "1Password"
    } else if identity.starts_with("SSH agent") {
        "SSH agent"
    } else if identity.starts_with("identity file") {
        "identity-file"
    } else {
        identity.split_whitespace().next().unwrap_or("unknown")
    }
}

/// `name: ssh-ed25519 SHA256:abcdefgh…` as `name SHA256:abcdefgh`.
fn short_recipient(recipient: &str) -> String {
    let (name, key) = recipient.split_once(": ").unwrap_or((recipient, ""));
    let fingerprint = key.split_whitespace().last().unwrap_or("");
    let short = match fingerprint.strip_prefix("SHA256:") {
        Some(hash) => format!("SHA256:{}", hash.chars().take(8).collect::<String>()),
        None => fingerprint.chars().take(16).collect(),
    };
    if short.is_empty() {
        name.to_owned()
    } else {
        format!("{name} {short}")
    }
}

/// The seconds until the request denies itself, if it counts down.
pub(crate) fn remaining_seconds(prompt: &SecretPrompt) -> Option<u64> {
    prompt
        .deadline
        .map(|deadline| deadline.saturating_duration_since(Instant::now()).as_secs())
}

/// The modal body. Long descriptions and commands wrap in the dialog.
pub(crate) fn body(prompt: &SecretPrompt, details: bool, width: usize) -> String {
    let source = key_source(&prompt.identity);
    let mut lines = Vec::new();
    // Inside a procedure the title names the step; this names who asked.
    if prompt.procedure.is_some() {
        lines.push(format!("{}.", title(prompt)));
        lines.push(String::new());
    }
    lines.extend([
        if prompt.closure_signature {
            format!("Approve to decrypt this signing key once with {source} and sign requester-supplied public Nix closure metadata on this client. This client has not verified NAR contents. Only signatures are returned.")
        } else if prompt.artifact_signature {
            format!("Approve to decrypt this signing key once with {source} and sign the verified artifacts on this client. Only detached signatures are returned.")
        } else if prompt.ssh_signature {
            "Approve one SSH authentication signature using this client's agent. The private SSH key stays on this client.".into()
        } else {
            format!("Approve to decrypt these once with {source}.")
        },
        String::new(),
        "Requestor provides unvalidated reason:".into(),
        prompt
            .reason
            .clone()
            .unwrap_or_else(|| "(none supplied)".into()),
        String::new(),
    ]);
    if details {
        return details_body(prompt, lines);
    }
    // Descriptions get their own lines so none are lost on narrow screens.
    let id_width = prompt
        .values
        .iter()
        .map(|value| UnicodeWidthStr::width(value.identifier.as_str()))
        .chain([UnicodeWidthStr::width("Identifier")])
        .max()
        .unwrap_or(0)
        .min(width * 3 / 5);
    let row = |identifier: &str, kind: &str| format!("{}  {kind}", pad(identifier, id_width));
    lines.push(row("Identifier", "Kind"));
    for value in &prompt.values {
        lines.push(row(&value.identifier, &value.kind));
        if let Some(description) = &value.description {
            lines.push(format!("  Description: {description}"));
        }
    }
    lines.push(String::new());
    let mut recipients: Vec<String> = Vec::new();
    for recipient in prompt.values.iter().flat_map(|value| &value.recipients) {
        let short = short_recipient(recipient);
        if !recipients.contains(&short) {
            recipients.push(short);
        }
    }
    let label = if recipients.len() == 1 {
        "Recipient"
    } else {
        "Recipients"
    };
    if !prompt.ssh_signature {
        lines.push(format!("{label:<10} {}", recipients.join(", ")));
    }
    lines.push(format!("{:<10} {source}", "Key"));
    let requester = &prompt.requester;
    lines.push(format!("{:<10} {}", "Command", requester.argv.join(" ")));
    if let Some(cwd) = &requester.cwd {
        lines.push(format!("{:<10} {cwd}", "Cwd"));
    }
    if let Some(parent) = &prompt.parent {
        lines.push(format!(
            "{:<10} via {} ({})",
            "Parent",
            program_name(parent),
            parent.pid
        ));
    }
    lines.join("\n")
}

fn details_body(prompt: &SecretPrompt, mut lines: Vec<String>) -> String {
    lines.push("Values:".into());
    for value in &prompt.values {
        lines.push(format!("• {} ({})", value.identifier, value.kind));
        if let Some(description) = &value.description {
            lines.push(format!("  {description}"));
        }
        for recipient in &value.recipients {
            lines.push(format!("  recipient {recipient}"));
        }
    }
    lines.push(String::new());
    lines.push(process_lines(
        "Requester",
        &crate::model::ProcessDisplay(&prompt.requester),
    ));
    if let Some(parent) = &prompt.parent {
        lines.push(process_lines(
            "Parent",
            &crate::model::ProcessDisplay(parent),
        ));
    }
    lines.push(String::new());
    if prompt.artifact_signature || prompt.closure_signature {
        lines.push(
            "Only detached signatures are returned. The private signing key stays on this client."
                .into(),
        );
    } else if prompt.ssh_signature {
        lines.push("Only this SSH authentication signature is returned. The private SSH key stays on this client.".into());
    } else {
        lines.push(format!("Decrypted with: {}", prompt.identity));
        lines.push(
            "The values go to the backend, which hands them only to this program until it exits."
                .into(),
        );
    }
    lines.join("\n")
}

fn pad(text: &str, width: usize) -> String {
    let used = UnicodeWidthStr::width(text);
    format!("{text}{}", " ".repeat(width.saturating_sub(used)))
}
