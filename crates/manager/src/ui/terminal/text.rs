use super::*;

pub(super) fn prompt(model: &Model) -> String {
    match &model.mode {
        Mode::Browse => selected_text(model),
        Mode::Help { .. } => "All actions are described above. Use ↑↓ to scroll.".into(),
        Mode::Search { query } => format!("Search: {query} · Enter: keep filter · Esc: clear"),
        Mode::DeleteConfirm { path } => format!("Delete {path} from encrypted store? y/n"),
        Mode::Reveal { .. } => "Esc: hide".into(),
        Mode::Edit { value, .. } => format!(
            "value: {}  (Enter saves, Esc cancels)",
            "•".repeat(value.len())
        ),
        Mode::Replace { path, .. } => format!("Replace {path}? y/n"),
        Mode::GenerateChoice { .. } => "Generate p: password · w: passphrase · Esc: cancel".into(),
        Mode::BulkGenerateConfirm { paths } => format!("Generate all {} missing password values? Existing values will be kept.\np: passwords · w: passphrases · Esc: cancel", paths.len()),
        Mode::BulkProgress { total, done } => format!("Generated {done} of {total} missing passwords.\nEsc: hide progress; generation continues"),
        Mode::GeneratedPreview {
            value, revealed, ..
        } => {
            let preview = if *revealed {
                std::str::from_utf8(value).unwrap_or("<non-UTF8 generated value>")
            } else {
                "••••••••"
            };
            format!("generated: {preview} · r: reveal/hide · c: copy · Enter: save · Esc: cancel")
        }
        Mode::ProviderFailure { message, .. } => {
            format!("Provider failed: {message}. r: retry · Esc: cancel")
        }
        Mode::Approval(request) => {
            let failure = model.message.as_deref().unwrap_or_default();
            if let Some(host_key) = &request.host_key {
                format!(
                    "{failure} {host_key} Trust this host and inspect its deployment state? y/n"
                )
            } else {
                format!(
                    "{failure} Deploy to {}? create [{}], replace [{}], tasks [{}], keys [{}] · y/n",
                    request.target,
                    request.create.join(", "),
                    request.replace.join(", "),
                    request.tasks.iter().map(task_status).collect::<Vec<_>>().join(", "),
                    request.recipient_keys.join(", ")
                )
            }
        }
    }
}

pub(super) fn selected_text(model: &Model) -> String {
    let description = model
        .selected()
        .and_then(|row| row.description.as_deref())
        .unwrap_or("");
    let path = model
        .selected()
        .map(|row| row.path.as_deref().unwrap_or(&row.name))
        .unwrap_or("none");
    if description.is_empty() {
        path.to_owned()
    } else {
        format!("{path}\n{description}")
    }
}

pub(super) fn legend_text(model: &Model, width: u16) -> String {
    if width < 45 {
        return match model.mode {
            Mode::Browse => "↑↓ move · Enter edit · ? help".into(),
            Mode::Help { .. } => "↑↓ scroll · Esc close".into(),
            Mode::Reveal { .. } => "↑↓ scroll · c copy · Esc hide".into(),
            _ => "Enter accept · Esc cancel · ? help from browse".into(),
        };
    }
    match model.mode {
        Mode::Browse => "↑↓ move · / search · 1–5 type · 6–7 audience · ? help\nEnter edit · g one · G missing · d delete · r reveal · c copy".into(),
        Mode::Help { .. } => "Help: ↑↓ scroll · Esc or ? close".into(),
        Mode::Reveal { .. } => "Reveal: ↑↓ scroll · c copy · Enter or Esc hide".into(),
        Mode::Search { .. } => "Search: type query · Backspace erase · Enter keep · Esc clear".into(),
        Mode::Approval(_) => "Deployment: y approve · n reject · Esc reject".into(),
        Mode::DeleteConfirm { .. } | Mode::Replace { .. } => "Confirm: y proceed · n cancel · Esc cancel".into(),
        Mode::GenerateChoice { .. } => "Generate: p password · w passphrase · Esc cancel".into(),
        Mode::BulkGenerateConfirm { .. } => "Generate missing: p passwords · w passphrases · Esc cancel".into(),
        Mode::BulkProgress { .. } => "Generating: Esc hide progress · result requires Enter".into(),
        Mode::GeneratedPreview { .. } => "Preview: r reveal · c copy · Enter save · Esc discard".into(),
        Mode::ProviderFailure { .. } => "Provider: r retry · Esc cancel".into(),
        Mode::Edit { .. } => "Edit: type or paste · Backspace erase · Enter save · Esc cancel".into(),
    }
}

pub(super) fn help_text() -> &'static str {
    "NAVIGATE\n↑ / ↓  Move between visible items\n/  Search names, identifiers, and descriptions\n1 Required · 2 All · 3 Keys · 4 Passwords · 5 Public info\n6 Everyone · 7 Human-facing\n?  Show or close this help\n\nEDIT\nEnter  Edit selected value; Enter again saves\nPaste  Set from clipboard; replacement asks first\ng  Generate password or passphrase for one field\nG  Generate all missing passwords; keeps existing values\nr  Reveal selected value\nc  Copy the selected value\np  Copy the public half of a stored OpenSSH private key\nd  Delete selected value after confirmation\n\nDEPLOYMENT\nA target deployer requests one server's values.\ny  Approve the verified target and displayed changes\nn / Esc  Reject the request\n\nEnter  Acknowledge a notice\nEsc  Leave a view, or quit from the tree"
}
