//! The deployment dialog: what a request will do, grouped by what happens to
//! each value, with colours and counts.
//!
//! Colours: red is an error, yellow is not deployed yet or a warning, cyan is generated on
//! the target, green is set or replaced, and dim is secondary text. Titles and
//! group headers are bold.
use crate::model::ApprovalRequest;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// The groups of values that cannot be deployed yet, in display order.
const BLOCKING: [&str; 4] = [
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

pub(crate) fn approval_title(request: &ApprovalRequest) -> String {
    if request.host_key.is_some() {
        format!("Deploy {} · step 1/2: verify the SSH host key", request.target)
    } else if !request.deployable() {
        format!("Deploy {} · nothing can be deployed yet", request.target)
    } else {
        format!("Deploy {} · step 2/2: review what will be deployed", request.target)
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

struct Group<'a> {
    title: &'a str,
    color: Color,
    rows: Vec<(String, String)>,
}

/// Every group of the request, in display order; empty groups left out.
fn groups(request: &ApprovalRequest) -> Vec<Group<'_>> {
    let mut groups = Vec::new();
    {
        for title in BLOCKING {
            let rows = request
                .missing
                .iter()
                .filter(|(identifier, _)| {
                    request
                        .missing_kinds
                        .get(identifier)
                        .map_or(title == "Needs input", |kind| kind == title)
                })
                .map(|(identifier, reason)| (identifier.clone(), reason.clone()))
                .collect();
            groups.push(Group {
                title,
                color: Color::Yellow,
                rows,
            });
        }
    }
    let waiting = |identifier: &String| request.missing.iter().any(|(id, _)| id == identifier);
    let generated = |identifier: &String| request.generate.iter().any(|(id, _)| id == identifier);
    let derived = |identifier: &String| request.derived.iter().any(|(id, _)| id == identifier);
    groups.push(Group {
        title: "Will be generated on the target",
        color: Color::Cyan,
        rows: request
            .generate
            .iter()
            .map(|(identifier, kind)| (identifier.clone(), kind.clone()))
            .collect(),
    });
    groups.push(Group {
        title: "Will be derived",
        color: Color::Cyan,
        rows: request
            .derived
            .iter()
            .filter(|(identifier, _)| !waiting(identifier))
            .map(|(identifier, source)| (identifier.clone(), format!("from {source}")))
            .collect(),
    });
    let plain = |list: &[String]| {
        list.iter()
            .filter(|identifier| !waiting(identifier) && !generated(identifier) && !derived(identifier))
            .map(|identifier| (identifier.clone(), String::new()))
            .collect::<Vec<_>>()
    };
    groups.push(Group {
        title: "Will be set",
        color: Color::Green,
        rows: plain(&request.create),
    });
    groups.push(Group {
        title: "Will be replaced",
        color: Color::Green,
        rows: plain(&request.replace),
    });
    groups.push(Group {
        title: "Target tasks",
        color: Color::Green,
        rows: request
            .tasks
            .iter()
            .map(|task| {
                (
                    task.identifier.clone(),
                    super::tree::task_status(task),
                )
            })
            .collect(),
    });
    groups.push(Group {
        title: "Uses the host's default",
        color: Color::Reset,
        rows: request
            .host_default
            .iter()
            .map(|identifier| (identifier.clone(), "public information installed by the host".into()))
            .collect(),
    });
    groups.retain(|group| !group.rows.is_empty());
    groups
}

/// The body lines for an inner width of `width` columns.
pub(crate) fn approval_lines(
    request: &ApprovalRequest,
    failure: Option<&str>,
    details: bool,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
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
        lines.push(Line::styled(host_key.clone(), Style::default().fg(Color::Yellow)));
        return lines;
    }
    let deployable = request.deployable();
    let missing = request.missing.len();
    lines.push(if !deployable {
        Line::styled(
            format!("Nothing of {} can be deployed yet. Every value is missing:", request.target),
            bold(Color::Red),
        )
    } else if missing > 0 {
        Line::styled(
            format!(
                "Deploy {}? {missing} value{} cannot be deployed yet and {} left out; {} waits only for {}.",
                request.target,
                if missing == 1 { "" } else { "s" },
                if missing == 1 { "is" } else { "are" },
                request.target,
                if missing == 1 { "it" } else { "them" },
            ),
            bold(Color::Yellow),
        )
    } else {
        Line::styled(
            format!("Deploy these values to {}?", request.target),
            Style::default().add_modifier(Modifier::BOLD),
        )
    });
    lines.push(Line::styled(
        "Each service waits only for its own values, so a partial deployment is safe.".to_owned(),
        dim(),
    ));
    lines.push(Line::default());
    lines.push(Line::styled(request.target.clone(), bold(Color::Reset)));
    let identifier_width = (width.saturating_sub(4) * 11 / 20).max(12);
    for group in groups(request) {
        lines.push(Line::styled(
            format!("  {} ({})", group.title, group.rows.len()),
            bold(group.color),
        ));
        for (identifier, reason) in &group.rows {
            let name = short(&request.target, identifier);
            if details {
                lines.push(Line::from(Span::styled(
                    format!("    {identifier}"),
                    Style::default().fg(group.color),
                )));
                if !reason.is_empty() {
                    lines.push(Line::styled(format!("      {reason}"), dim()));
                }
                continue;
            }
            let name = fit(name, identifier_width);
            let used = 4 + unicode_width::UnicodeWidthStr::width(name.as_str());
            let mut spans = vec![Span::styled(
                format!("    {name}"),
                Style::default().fg(group.color),
            )];
            if !reason.is_empty() && width > used + 4 {
                spans.push(Span::styled(
                    format!("  {}", fit(reason, width - used - 2)),
                    dim(),
                ));
            }
            lines.push(Line::from(spans));
        }
    }
    if deployable && !request.recipient_keys.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("Decrypt with ".to_owned(), dim()),
            Span::raw(
                request
                    .recipient_keys
                    .iter()
                    .map(|key| fit(key, 24))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        ]));
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
