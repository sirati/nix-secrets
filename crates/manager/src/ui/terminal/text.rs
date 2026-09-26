mod width;
use super::*;
use width::{ellipsize, shorten};

/// The label of the autosave checkbox in the entry field.
pub(super) const AUTOSAVE_LABEL: &str = "Autosave unset on paste (disable in settings/restart)";

pub(super) fn prompt(model: &Model) -> String {
    if let Some(items) = selector_items(model) {
        let header = match &model.mode {
            Mode::FacetCategories { .. } => "Choose an attribute to filter. Tree and filter-only attributes are both available.",
            Mode::FacetValues { .. } => "Choose All, Whitelist, Blacklist, or toggle a value. Switching lists preserves visible values.",
            Mode::FacetFirstChoice { .. } => "Choose the first filter rule for this value:",
            Mode::TreeOrder { .. } => "Space moves an attribute into/out of the tree. [ and ] reorder tree attributes.",
            Mode::Profiles { .. } => "Enter loads a profile; n creates one; s overwrites the selected profile; d deletes it.",
            Mode::Settings { .. } => "Settings last for this session only; they reset when nix-secrets restarts.",
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
                    if let Some(value) = attribute.value(row) {
                        text.push_str(&format!("{}: {value}\n", attribute.label()));
                    }
                }
                text.push_str(&format!("\nStorage identifier: {}", row.path.as_deref().unwrap_or("(none)")));
                text
            } else { "No selection".into() }
        }
        Mode::Help { .. } => "All actions are described above. Use ↑↓ to scroll.".into(),
        Mode::Search { query } => format!("Search: {query} · Enter: keep filter · Esc: clear"),
        Mode::ProfileSave { name } => format!("Name: {name} · Enter saves current view · Esc cancels"),
        Mode::ProfileOverwrite { name } => format!("Replace view profile {name} with current layout? y/n"),
        Mode::ProfileDelete { name } => format!("Delete view profile {name}? y/n"),
        Mode::DeleteConfirm { path } => format!("Delete {path} from encrypted store? y/n"),
        Mode::Reveal { .. } => "Esc: hide".into(),
        Mode::Edit { value, .. } => format!(
            "value: {}  (Enter saves, Esc cancels)\n\n{} {AUTOSAVE_LABEL} · Tab or click toggles",
            "•".repeat(value.len()),
            if model.settings.autosave_unset_on_paste { "☑" } else { "□" }
        ),
        Mode::Replace { path, commit, .. } => match commit {
            nix_secrets_core::CommitState::Committed | nix_secrets_core::CommitState::Unset => {
                format!("Replace {path}? y/n")
            }
            nix_secrets_core::CommitState::Uncommitted => format!(
                "The current value of {path} was never committed to git. Overwriting it will lose the old value irrevocably. Overwrite?\n\nCtrl+Shift+Y: overwrite · n, Enter, Space or Esc: keep it"
            ),
            nix_secrets_core::CommitState::Unknown { reason } => format!(
                "Whether the current value of {path} is committed to git could not be checked ({reason}), so it is treated as never committed. Overwriting it may lose the old value irrevocably. Overwrite?\n\nCtrl+Shift+Y: overwrite · n, Enter, Space or Esc: keep it"
            ),
        },
        Mode::Settings { .. } => unreachable!("settings render as a selector"),
        Mode::GenerateChoice { .. } => "Generate p: password · w: passphrase · Esc: cancel".into(),
        Mode::KeypairConfirm { path, replacing } => format!(
            "Run the declared generator for {path}? It runs `nix run` locally; the private key is encrypted at once and the public key is stored in plain.{}\ny: generate · Esc: cancel",
            if *replacing { " The current key will be REPLACED." } else { "" }
        ),
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
            let failure = model.message_text().unwrap_or_default();
            if let Some(host_key) = &request.host_key {
                format!(
                    "{failure} {host_key} Trust this host and inspect its deployment state? y/n"
                )
            } else if !request.missing.is_empty() {
                format!(
                    "{failure} Cannot deploy to {}: missing values that must be entered: {}. Nothing will be generated or written. n: dismiss",
                    request.target,
                    request
                        .missing
                        .iter()
                        .map(|(id, reason)| format!("{id} ({reason})"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                let generate = if request.generate.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", will generate {} values on the target: [{}]",
                        request.generate.len(),
                        request
                            .generate
                            .iter()
                            .map(|(id, kind)| format!("{id} ({kind})"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                let generate = if request.derived.is_empty() {
                    generate
                } else {
                    format!(
                        "{generate}, derived [{}]",
                        request
                            .derived
                            .iter()
                            .map(|(id, source)| format!("{id} from {source}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                format!(
                    "{failure} Deploy to {}? create [{}], replace [{}], tasks [{}]{generate}, keys [{}] · y/n",
                    request.target,
                    request.create.join(", "),
                    request.replace.join(", "),
                    request.tasks.iter().map(task_status).collect::<Vec<_>>().join(", "),
                    request.recipient_keys.join(", ")
                )
            }
        }
        Mode::FacetCategories { .. } | Mode::FacetValues { .. } | Mode::FacetFirstChoice { .. } | Mode::TreeOrder { .. } | Mode::Profiles { .. } => unreachable!(),
    }
}

pub(super) fn selector_items(model: &Model) -> Option<Vec<String>> {
    use crate::model::{Attribute, FacetMode};
    match &model.mode {
        Mode::FacetCategories { selected } => Some(
            Attribute::GROUPING
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
        Mode::Settings { selected } => Some(
            crate::model::Settings::ITEMS
                .iter()
                .enumerate()
                .map(|(index, setting)| {
                    format!(
                        "{} {} {}",
                        marker(*selected, index),
                        if model.settings.get(*setting) {
                            "☑"
                        } else {
                            "□"
                        },
                        setting.label()
                    )
                })
                .collect(),
        ),
        Mode::Profiles { selected } => Some(
            std::iter::once(format!(
                "{} Save current view as new profile",
                marker(*selected, 0)
            ))
            .chain(
                model
                    .profiles
                    .profiles
                    .keys()
                    .enumerate()
                    .map(|(index, name)| {
                        let active = model.active_profile.as_deref() == Some(name.as_str());
                        format!(
                            "{} {}{}",
                            marker(*selected, index + 1),
                            name,
                            if active { " · active" } else { "" }
                        )
                    }),
            )
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
        Mode::Profiles { selected } | Mode::Settings { selected } => Some(*selected),
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
            crate::tree::RowCategory::Operator => "operator key, never deployed",
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
