//! The procedure task bar: one entry per procedure with its title, current
//! step and whether it waits for the operator. A click restores an entry;
//! one that arrived while something else was open flashes until restored.
use super::*;
use crate::model::Procedure;
use ratatui::style::Modifier;

/// What the procedure is doing, for its entry.
pub(super) fn state(model: &Model, procedure: &Procedure) -> String {
    if let Some(prompt) = procedure.prompts.front() {
        return match super::super::secret_request::remaining_seconds(prompt) {
            Some(seconds) => format!("waiting for you · denies in {seconds} s"),
            None => "waiting for you".into(),
        };
    }
    if procedure.failed() {
        "failed · waiting for you".into()
    } else if model.procedure_waiting(procedure) {
        "waiting for you".into()
    } else if matches!(
        procedure.between,
        Some(crate::model::Between::Result { succeeded: true, .. })
    ) {
        "done".into()
    } else if procedure.awaiting_deployment {
        "deployment queued behind the open one".into()
    } else {
        "working".into()
    }
}

/// One entry's text.
pub(super) fn entry(model: &Model, procedure: &Procedure) -> String {
    let marker = if model.foreground.as_deref() == Some(procedure.id.as_str())
        && !procedure.minimised
    {
        "▸"
    } else {
        "▪"
    };
    format!("{marker} {} · {}", procedure.heading(), state(model, procedure))
}

fn style(model: &Model, procedure: &Procedure) -> Style {
    if procedure.flashing {
        // Alternates on every flash phase.
        return if model.flash_on {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        };
    }
    if model.procedure_waiting(procedure) {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().add_modifier(Modifier::DIM)
    }
}

pub(super) fn render_taskbar(
    frame: &mut ratatui::Frame<'_>,
    model: &Model,
    zone: Rect,
    hits: &mut HitMap,
) {
    if zone.height == 0 || model.procedures.is_empty() {
        return;
    }
    if zone.height < 3 {
        // One plain line: the entries side by side, each as wide as fits.
        let count = model.procedures.len() as u16;
        let width = (zone.width / count).max(1);
        let mut spans = Vec::new();
        for (index, procedure) in model.procedures.iter().enumerate() {
            let text = ellipsize(&entry(model, procedure), width.saturating_sub(1) as usize);
            let x = zone.x + width * index as u16;
            if x >= zone.right() {
                break;
            }
            hits.add(
                Rect {
                    x,
                    y: zone.y,
                    width: width.min(zone.right() - x),
                    height: 1,
                },
                MouseTarget::Procedure(index),
            );
            spans.push(Span::styled(
                format!("{text:<width$}", width = width as usize),
                style(model, procedure),
            ));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), zone);
        return;
    }
    frame.render_widget(
        Block::default()
            .title("Procedures · M restores the next waiting · m minimises")
            .borders(Borders::ALL),
        zone,
    );
    let rows = zone.height.saturating_sub(2) as usize;
    let inner = zone.width.saturating_sub(2);
    let mut lines = Vec::new();
    for (index, procedure) in model.procedures.iter().enumerate().take(rows) {
        let more = model.procedures.len() - index - 1;
        let text = if index + 1 == rows && more > 0 {
            format!("{} more, flashing ones first with M", more + 1)
        } else {
            entry(model, procedure)
        };
        let y = zone.y + 1 + index as u16;
        hits.add(
            Rect {
                x: zone.x + 1,
                y,
                width: inner,
                height: 1,
            },
            MouseTarget::Procedure(index),
        );
        lines.push(Line::styled(ellipsize(&text, inner as usize), style(model, procedure)));
    }
    frame.render_widget(
        Paragraph::new(lines),
        Rect {
            x: zone.x + 1,
            y: zone.y + 1,
            width: inner,
            height: rows as u16,
        },
    );
}
