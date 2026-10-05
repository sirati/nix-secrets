//! The deployment dialog: what a request will do, one row per value.
//!
//! Two sections have a checkbox on every row, checked at first: "Will be
//! sent" and "Will be generated". Space toggles the row under the cursor,
//! `a` its whole section, and a click on a row (label included) toggles it.
//! Approving sends exactly the checked rows. Values that cannot be deployed
//! are listed under "Missing", grouped by why, without a checkbox.
//!
//! Colours: red is an error, yellow is missing or a warning, cyan is
//! generated on the target, green is sent, and dim is secondary text.
//! Titles and headers are bold.
use crate::model::{ApprovalRequest, DeployRow, Section};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// The groups of values that cannot be deployed, in display order.
const MISSING: [&str; 5] = [
    "Optional; not provided",
    "Cannot deploy",
    "Needs input",
    "Filled by another host",
    "Derived from unset source",
];

fn bold(color: Color) -> Style {
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

fn dim() -> Style {
    Style::default().add_modifier(Modifier::DIM)
}

/// The three steps of a deployment: host key, review, deploy.
pub(crate) fn approval_title(request: &ApprovalRequest) -> String {
    if !request.host_mutations.is_empty() {
        "Save host-provided changes".into()
    } else if request.host_key.is_some() {
        format!(
            "Deploy {} · step 1/3: verify the SSH host key",
            request.target
        )
    } else if request.rows().is_empty() {
        format!("Deploy {} · nothing can be deployed yet", request.target)
    } else {
        format!("Deploy {} · step 2/3: choose what to deploy", request.target)
    }
}

/// `ns1.services.dns.update-key` under the `ns1` header as
/// `services.dns.update-key`.
fn short<'a>(target: &str, identifier: &'a str) -> &'a str {
    identifier
        .strip_prefix(target)
        .and_then(|rest| rest.strip_prefix('.'))
        .unwrap_or(identifier)
}

fn fit(text: &str, width: usize) -> String {
    super::text::ellipsize(text, width)
}

fn width_of(text: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(text)
}

/// The missing values by group, empty groups left out.
fn missing_groups(request: &ApprovalRequest) -> Vec<(&'static str, Vec<(String, String)>)> {
    MISSING
        .iter()
        .map(|title| {
            let rows = request
                .missing
                .iter()
                .filter(|(identifier, _)| {
                    request
                        .missing_kinds
                        .get(identifier)
                        .map_or(*title == "Needs input", |kind| kind == title)
                })
                .cloned()
                .collect::<Vec<_>>();
            (*title, rows)
        })
        .filter(|(_, rows)| !rows.is_empty())
        .collect()
}

/// The width a row's identifier and the text before it need, for sizing
/// the dialog: never narrower than the longest header or identifier.
pub(crate) fn needed_width(request: &ApprovalRequest, details: bool) -> usize {
    let name = |identifier: &str| {
        if details {
            identifier.to_owned()
        } else {
            short(&request.target, identifier).to_owned()
        }
    };
    let rows = request
        .rows()
        .iter()
        .map(|row| 8 + width_of(&name(&row.identifier)))
        .chain(
            request
                .missing
                .iter()
                .map(|(identifier, _)| 6 + width_of(&name(identifier))),
        )
        .chain(MISSING.iter().map(|title| 4 + width_of(title) + 6))
        .chain([
            width_of("  Will be generated on the target (000)"),
            width_of(&approval_title(request)) + 2,
            width_of(&format!("Request: {}", request.id)),
        ])
        .max()
        .unwrap_or(0);
    rows
}

/// Where each checkbox row is among the body lines, for mouse hits: the
/// line index and the row's identifier.
pub(crate) fn checkbox_lines(
    request: &ApprovalRequest,
    failure: Option<&str>,
    details: bool,
    width: usize,
) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    for (index, line) in approval_lines(request, failure, details, width).iter().enumerate() {
        let text = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        if let Some(rest) = text.strip_prefix("  [x] ").or_else(|| text.strip_prefix("  [ ] ")) {
            let rest = rest.strip_prefix("▸ ").unwrap_or(rest);
            let rows = request.rows();
            let name = |row: &DeployRow| {
                if details {
                    row.identifier.clone()
                } else {
                    short(&request.target, &row.identifier).to_owned()
                }
            };
            // The row whose whole name starts the line; the longest wins.
            if let Some(row) = (0..rows.len())
                .filter(|index| {
                    let name = name(&rows[*index]);
                    rest == name || rest.starts_with(&format!("{name} "))
                })
                .max_by_key(|index| name(&rows[*index]).len())
            {
                found.push((index, row));
            }
        }
    }
    found
}

/// The body lines for an inner width of `width` columns.
pub(crate) fn approval_lines(
    request: &ApprovalRequest,
    failure: Option<&str>,
    details: bool,
    width: usize,
) -> Vec<Line<'static>> {
    if !request.host_mutations.is_empty() {
        return host_mutation_lines(request, failure);
    }
    let mut lines = Vec::new();
    if !request.id.is_empty() {
        lines.push(Line::raw(format!("Request: {}", request.id)));
        lines.push(Line::default());
    }
    if let Some(failure) = failure.filter(|text| !text.is_empty()) {
        lines.push(Line::styled(failure.to_owned(), bold(Color::Red)));
        lines.push(Line::default());
    }
    if let Some(host_key) = &request.host_key {
        lines.push(Line::styled(
            "Connect to the target over SSH as its forwarder account.".to_owned(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::styled(
            "Nothing is decrypted in this step: approving only trusts this host key and reads the target's deployment state."
                .to_owned(),
            dim(),
        ));
        lines.push(Line::default());
        lines.push(Line::styled(
            host_key.clone(),
            Style::default().fg(Color::Yellow),
        ));
        if let Some(key) = &request.login_key {
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled("Log in with ".to_owned(), dim()),
                Span::raw(key.to_string()),
            ]));
        }
        return lines;
    }
    let rows = request.rows();
    let checked = request.checked();
    let missing = request.missing.len();
    lines.push(if rows.is_empty() {
        Line::styled(
            format!("Nothing of {} can be deployed yet:", request.target),
            bold(Color::Red),
        )
    } else {
        Line::styled(
            format!(
                "Deploy {} of {} value{} to {}?",
                checked.len(),
                rows.len(),
                if rows.len() == 1 { "" } else { "s" },
                request.target
            ),
            Style::default().add_modifier(Modifier::BOLD),
        )
    });
    if !rows.is_empty() {
        lines.push(Line::styled(
            "Space toggles, a toggles the section, ↑↓ move. Unchecked and missing values are left out; each service waits only for its own values."
                .to_owned(),
            dim(),
        ));
    }
    let name = |identifier: &str| -> String {
        if details {
            identifier.to_owned()
        } else {
            short(&request.target, identifier).to_owned()
        }
    };
    // Rows keep their identifier whole; only the explanation is cut.
    let row_line = |lines: &mut Vec<Line<'static>>,
                        prefix: String,
                        identifier: String,
                        what: &str,
                        color: Color| {
        let used = width_of(&prefix) + width_of(&identifier);
        let mut spans = vec![
            Span::raw(prefix),
            Span::styled(identifier, Style::default().fg(color)),
        ];
        if !what.is_empty() {
            if details || width < used + 6 {
                lines.push(Line::from(spans));
                lines.push(Line::styled(format!("        {}", what), dim()));
                return;
            }
            spans.push(Span::styled(
                format!("  {}", fit(what, width - used - 2)),
                dim(),
            ));
        }
        lines.push(Line::from(spans));
    };
    let mut index = 0;
    for (section, title, color) in [
        (Section::Sent, "Will be sent", Color::Green),
        (
            Section::Generated,
            "Will be generated on the target",
            Color::Cyan,
        ),
    ] {
        let section_rows = rows
            .iter()
            .filter(|row| row.section == section)
            .collect::<Vec<&DeployRow>>();
        if section_rows.is_empty() {
            continue;
        }
        lines.push(Line::default());
        let on = section_rows
            .iter()
            .filter(|row| !request.unchecked.contains(&row.identifier))
            .count();
        lines.push(Line::styled(
            format!("{title} ({on}/{})", section_rows.len()),
            bold(color),
        ));
        for row in section_rows {
            let mark = if request.unchecked.contains(&row.identifier) { "[ ]" } else { "[x]" };
            let cursor = if index == request.cursor { "▸ " } else { "" };
            row_line(
                &mut lines,
                format!("  {mark} {cursor}"),
                name(&row.identifier),
                &row.what,
                color,
            );
            index += 1;
        }
    }
    if missing > 0 {
        lines.push(Line::default());
        lines.push(Line::styled(
            format!("Missing ({missing})"),
            bold(Color::Yellow),
        ));
        for (title, group) in missing_groups(request) {
            lines.push(Line::styled(
                format!("  {title} ({})", group.len()),
                bold(Color::Yellow),
            ));
            for (identifier, reason) in group {
                row_line(
                    &mut lines,
                    "    ".into(),
                    name(&identifier),
                    &reason,
                    Color::Yellow,
                );
            }
        }
    }
    if !request.host_default.is_empty() {
        lines.push(Line::default());
        lines.push(Line::styled(
            format!("Uses the host's default ({})", request.host_default.len()),
            bold(Color::Reset),
        ));
        for identifier in &request.host_default {
            row_line(
                &mut lines,
                "    ".into(),
                name(identifier),
                "public information installed by the host",
                Color::Reset,
            );
        }
    }
    let decrypts = checked.iter().any(|row| row.section == Section::Sent);
    if decrypts && !request.recipient_keys.is_empty() {
        lines.push(Line::default());
        for key in &request.recipient_keys {
            lines.push(Line::from(vec![
                Span::styled("Decrypt with ".to_owned(), dim()),
                Span::raw(key.clone()),
            ]));
        }
    }
    lines
}

/// The plain text of styled lines, for measuring.
pub(crate) fn plain(lines: &[Line<'_>]) -> String {
    lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn host_mutation_lines(request: &ApprovalRequest, failure: Option<&str>) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::raw(format!("Request: {}", request.id)),
        Line::raw(format!("Source host: {}", request.target)),
        Line::default(),
        Line::styled("The target deployment already completed. Existing nonempty TOML values have not been replaced.", dim()),
        Line::styled("Save exactly the changes below? Rejecting keeps the existing values.", bold(Color::Yellow)),
    ];
    if let Some(failure) = failure {
        lines.push(Line::styled(failure.to_owned(), bold(Color::Red)));
    }
    for change in &request.host_mutations {
        lines.push(Line::default());
        lines.push(Line::styled(
            format!("Path: {}", change.identifier),
            bold(Color::Cyan),
        ));
        lines.push(Line::raw(format!("Purpose: {}", change.kind)));
        lines.push(Line::styled("Existing fingerprints:", dim()));
        for value in &change.previous {
            lines.push(Line::raw(format!("  {value}")));
        }
        lines.push(Line::styled("Proposed fingerprints:", bold(Color::Yellow)));
        for value in &change.proposed {
            lines.push(Line::raw(format!("  {value}")));
        }
    }
    lines
}
