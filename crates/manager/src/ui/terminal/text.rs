use super::*;

pub(super) fn prompt(model: &Model) -> String {
    if let Some(items) = selector_items(model) {
        let header = match &model.mode {
            Mode::FacetCategories { .. } => "Choose an attribute to filter. Tree and filter-only attributes are both available.",
            Mode::FacetValues { .. } => "Choose All, Whitelist, Blacklist, or toggle a value. Switching lists preserves visible values.",
            Mode::FacetFirstChoice { .. } => "Choose the first filter rule for this value:",
            Mode::TreeOrder { .. } => "Space moves an attribute into/out of the tree. [ and ] reorder tree attributes.",
            _ => unreachable!(),
        };
        return format!("{header}\n\n{}", items.join("\n"));
    }
    match &model.mode {
        Mode::Browse => selected_text(model, 80),
        Mode::Properties { .. } => {
            if let Some(row) = model.selected() {
                let mut text = format!("{}\n\n", model.selected_display_path().unwrap_or_else(|| row.name.clone()));
                for attribute in crate::model::Attribute::ALL {
                    text.push_str(&format!("{}: {}\n", attribute.label(), attribute.value(row)));
                }
                text.push_str(&format!("\nStorage identifier: {}", row.path.as_deref().unwrap_or("(none)")));
                text
            } else { "No selection".into() }
        }
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
        Mode::FacetCategories { .. } | Mode::FacetValues { .. } | Mode::FacetFirstChoice { .. } | Mode::TreeOrder { .. } => unreachable!(),
    }
}

pub(super) fn selector_items(model: &Model) -> Option<Vec<String>> {
    use crate::model::{Attribute, FacetMode};
    match &model.mode {
        Mode::FacetCategories { selected } => Some(
            Attribute::ALL
                .iter()
                .enumerate()
                .map(|(index, attribute)| {
                    let location = model
                        .tree_order
                        .iter()
                        .position(|item| item == attribute)
                        .map(|position| format!("tree {}", position + 1))
                        .unwrap_or_else(|| "filter only".into());
                    format!(
                        "{} {} · {}",
                        marker(*selected, index),
                        attribute.label(),
                        location
                    )
                })
                .collect(),
        ),
        Mode::FacetValues {
            attribute,
            selected,
        } => {
            let facet = model.facet(*attribute);
            let mut items = [FacetMode::All, FacetMode::Whitelist, FacetMode::Blacklist]
                .into_iter()
                .enumerate()
                .map(|(index, mode)| {
                    let label = match mode {
                        FacetMode::All => "All",
                        FacetMode::Whitelist => "Whitelist",
                        FacetMode::Blacklist => "Blacklist",
                    };
                    format!(
                        "{} {} {}",
                        marker(*selected, index),
                        if facet.mode == mode { "●" } else { "○" },
                        label
                    )
                })
                .collect::<Vec<_>>();
            items.extend(model.facet_values(*attribute).into_iter().enumerate().map(
                |(index, value)| {
                    let selected_value = facet.selected.contains(&value);
                    format!(
                        "{} {} {}",
                        marker(*selected, index + 3),
                        if selected_value { "☑" } else { "□" },
                        shorten(&value, 58)
                    )
                },
            ));
            Some(items)
        }
        Mode::FacetFirstChoice { attribute, value } => Some(
            [
                format!("1 Only this {} value", attribute.label()),
                "2 Only others (blacklist this value)".into(),
                "3 Whitelist with this value off".into(),
                "4 Blacklist with all other values off".into(),
            ]
            .into_iter()
            .map(|item| format!("{item}  [{}]", shorten(value, 24)))
            .collect(),
        ),
        Mode::TreeOrder { selected } => Some(
            model
                .tree_editor_attributes()
                .iter()
                .enumerate()
                .map(|(index, attribute)| {
                    let position = model.tree_order.iter().position(|item| item == attribute);
                    format!(
                        "{} {} {}",
                        marker(*selected, index),
                        position
                            .map(|value| format!("{}. tree", value + 1))
                            .unwrap_or_else(|| "filter only".into()),
                        attribute.label()
                    )
                })
                .collect(),
        ),
        _ => None,
    }
}

pub(super) fn selector_selected(model: &Model) -> Option<usize> {
    match &model.mode {
        Mode::FacetCategories { selected }
        | Mode::FacetValues { selected, .. }
        | Mode::TreeOrder { selected } => Some(*selected),
        Mode::FacetFirstChoice { .. } => Some(0),
        _ => None,
    }
}

fn marker(selected: usize, index: usize) -> &'static str {
    if selected == index {
        ">"
    } else {
        " "
    }
}

fn shorten(value: &str, max: usize) -> String {
    use unicode_width::UnicodeWidthStr;
    if UnicodeWidthStr::width(value) <= max {
        return value.into();
    }
    let mut output = String::new();
    for character in value.chars() {
        if UnicodeWidthStr::width(output.as_str())
            + unicode_width::UnicodeWidthChar::width(character).unwrap_or(0)
            + 1
            > max
        {
            break;
        }
        output.push(character);
    }
    output.push('…');
    output
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
            crate::tree::RowCategory::Password => "passphrase",
            crate::tree::RowCategory::Key if row.can_copy_public => "private key",
            crate::tree::RowCategory::Key => "key",
            crate::tree::RowCategory::PublicInfo => "public info",
            crate::tree::RowCategory::Other => "value",
        }
    };
    let kind = row
        .presentation
        .as_ref()
        .map(|presentation| presentation.value_type.as_str())
        .unwrap_or(kind);
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
    if let Some(description) = row
        .presentation
        .as_ref()
        .map(|presentation| &presentation.explanation)
        .or(row.description.as_ref())
    {
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
    "NAVIGATE\n↑ / ↓  Move between visible items\n/  Search names, identifiers, and explanations\nP  Show all attributes of the selected value\nF  Filter by any identity or presentation attribute\nT  Choose which attributes form the tree and reorder them\n1 Required (external values only) · 2 All · 3 Keys · 4 Passwords · 5 Public info\n6 Everyone · 7 Human-facing\n?  Show or close this help\n\nFACET FILTERS\nChoose an attribute, then All, Whitelist, Blacklist, or a value.\nSwitching Whitelist and Blacklist inverts checked values to preserve the visible set.\nFrom All, click a value for four choices: only this, only others,\nwhitelist this off, or blacklist all other values off.\nTree attributes remain filterable.\n\nEDIT\nEnter  Edit selected value; Enter again saves\nPaste  Set from clipboard; replacement asks first\ng  Generate password or passphrase for one field\nG  Generate all missing passwords; keeps existing values\nr  Reveal selected value\nc  Copy the selected value\np  Copy the public half of a stored OpenSSH private key\nd  Delete selected value after confirmation\n\nDEPLOYMENT\nA target deployer requests one server's values.\ny  Approve the verified target and displayed changes\nn / Esc  Reject the request\n\nEnter  Acknowledge a notice\nEsc  Leave a view, or quit from the tree"
}
