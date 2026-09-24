use super::*;

pub(super) fn prompt(model: &Model) -> String {
    match &model.mode {
        Mode::Browse => selected_text(model, 80),
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

pub(super) fn selected_text(model: &Model, width: u16) -> String {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
    let Some(row) = model.selected() else {
        return "none".into();
    };
    let path = model
        .selected_display_path()
        .unwrap_or_else(|| row.name.clone());
    let available = width.max(1) as usize;
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0;
    for character in path.chars() {
        let size = UnicodeWidthChar::width(character).unwrap_or(0);
        if used + size > available && !line.is_empty() {
            lines.push(std::mem::take(&mut line));
            used = 0;
        }
        line.push(character);
        used += size;
    }
    if !line.is_empty() {
        lines.push(line);
    }
    let kind = if row.is_task() {
        "generated task"
    } else {
        match row.category {
            crate::tree::RowCategory::Branch => "group",
            crate::tree::RowCategory::Password => "password",
            crate::tree::RowCategory::Key if row.can_copy_public => "private key",
            crate::tree::RowCategory::Key => "key",
            crate::tree::RowCategory::PublicInfo => "public info",
            crate::tree::RowCategory::Other => "value",
        }
    };
    let suffix = format!(" ({kind}) - ");
    if lines.is_empty() {
        lines.push(String::new());
    }
    let new_line = UnicodeWidthStr::width(lines.last().unwrap().as_str())
        + UnicodeWidthStr::width(suffix.as_str())
        > available;
    if new_line {
        lines.push(String::new());
    }
    let last = lines.last_mut().unwrap();
    last.push_str(if new_line {
        suffix.trim_start()
    } else {
        &suffix
    });
    if let Some(description) = &row.description {
        let explanation = description.split_whitespace().collect::<Vec<_>>().join(" ");
        let budget = available.saturating_sub(UnicodeWidthStr::width(last.as_str()));
        last.push_str(&ellipsize(&explanation, budget));
    }
    lines.join("\n")
}

fn ellipsize(value: &str, width: usize) -> String {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
    if UnicodeWidthStr::width(value) <= width {
        return value.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let mut output = String::new();
    let mut used = 0;
    for character in value.chars() {
        let size = UnicodeWidthChar::width(character).unwrap_or(0);
        if used + size + 1 > width {
            break;
        }
        output.push(character);
        used += size;
    }
    output.push('…');
    output
}

pub(super) fn help_text() -> &'static str {
    "NAVIGATE\n↑ / ↓  Move between visible items\n/  Search names, identifiers, and descriptions\n1 Required (external values only) · 2 All · 3 Keys · 4 Passwords · 5 Public info\n6 Everyone · 7 Human-facing\n?  Show or close this help\n\nEDIT\nEnter  Edit selected value; Enter again saves\nPaste  Set from clipboard; replacement asks first\ng  Generate password or passphrase for one field\nG  Generate all missing passwords; keeps existing values\nr  Reveal selected value\nc  Copy the selected value\np  Copy the public half of a stored OpenSSH private key\nd  Delete selected value after confirmation\n\nDEPLOYMENT\nA target deployer requests one server's values.\ny  Approve the verified target and displayed changes\nn / Esc  Reject the request\n\nEnter  Acknowledge a notice\nEsc  Leave a view, or quit from the tree"
}
