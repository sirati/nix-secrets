use super::*;
use ratatui::layout::{Alignment, Rect};
use ratatui::widgets::{Block, Borders, Clear};

mod actions;
mod buttons;
mod filters;
mod frontend;
mod help;
mod hit;
mod layout;
mod text;
mod tree;
use actions::hotkeys;
use buttons::{draw_rows, wrap_buttons};
use filters::render_filters;
use frontend::CrosstermFrontend;
use help::help_text;
use hit::HitMap;
use layout::regions;
use text::{prompt, selected_text, selector_items, selector_selected};
use tree::{render_tree, task_status};

pub fn run(rows: Vec<Row>, writer: &mut impl SecretWriter) -> io::Result<()> {
    let mut frontend = CrosstermFrontend::setup()?;
    let result = drive(&mut frontend, writer, &mut Model::new(rows));
    result.and(frontend.restore())
}

fn render(frame: &mut ratatui::Frame<'_>, model: &Model) -> HitMap {
    let area = frame.area();
    let selected = selected_text(model, area.width.saturating_sub(2));
    let zones = regions(area, selected.lines().count() as u16);
    let mut hits = HitMap::default();
    render_filters(frame, model, zones.filters, &mut hits);
    if zones.tree.height > 0 {
        render_tree(frame, model, zones.tree, &mut hits);
    }
    if zones.selected.height > 0 {
        frame.render_widget(
            Paragraph::new(selected)
                .block(Block::default().title("Selected").borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            zones.selected,
        );
    }
    if zones.status.height > 0 {
        let status = if model.message.is_some() {
            "Notice pending · Enter acknowledges".to_owned()
        } else if matches!(model.mode, Mode::BulkProgress { .. }) {
            "Generating passwords".to_owned()
        } else {
            model
                .active_profile
                .as_deref()
                .map(|name| {
                    if model.profile_dirty() {
                        format!("View: {name} (modified)")
                    } else {
                        format!("View: {name}")
                    }
                })
                .unwrap_or_else(|| "Ready".into())
        };
        frame.render_widget(
            Paragraph::new(status).block(Block::default().title("Status").borders(Borders::ALL)),
            zones.status,
        );
    }
    if zones.keys.height > 0 {
        frame.render_widget(
            Block::default()
                .title("Actions · ? for help")
                .borders(Borders::ALL),
            zones.keys,
        );
        let buttons = hotkeys(model, zones.keys.width < 70);
        let rows = wrap_buttons(
            buttons,
            zones.keys.width.saturating_sub(2),
            zones.keys.height.saturating_sub(2) as usize,
        );
        draw_rows(frame, zones.keys, rows, model.hover, &mut hits);
    }
    render_modal(frame, model, area, &mut hits);
    hits
}

fn render_modal(frame: &mut ratatui::Frame<'_>, model: &Model, area: Rect, hits: &mut HitMap) {
    let (title, body, scroll) = if let Some(message) = &model.message {
        (
            "Notice",
            format!("{message}\n\n↑↓: scroll · Enter: continue"),
            model.modal_scroll,
        )
    } else {
        match &model.mode {
            Mode::Browse => return,
            Mode::Help { scroll } => ("Help", help_text().to_owned(), *scroll),
            Mode::Properties { scroll } => ("Properties", prompt(model), *scroll),
            Mode::Reveal { value, scroll, .. } => (
                "Reveal",
                format!(
                    "{}\n\nEsc: hide · c: copy",
                    std::str::from_utf8(value).unwrap_or("<binary value: use c to copy>")
                ),
                *scroll,
            ),
            mode => (modal_title(mode), prompt(model), model.modal_scroll),
        }
    };
    if area.width == 0 || area.height == 0 {
        return;
    }
    hits.regions.clear();
    let width = area.width.min(80).max(1);
    let inner_width = width.saturating_sub(2).max(1) as usize;
    let selector = selector_items(model);
    let lines = if selector.is_some() {
        body.lines().count()
    } else {
        body.lines()
            .map(|line| line.chars().count().div_ceil(inner_width).max(1))
            .sum::<usize>()
    };
    let height = area.height.min((lines + 4).max(5) as u16);
    let box_area = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, box_area);
    frame.render_widget(
        Block::default().title(title).borders(Borders::ALL),
        box_area,
    );
    let body_area = Rect {
        x: box_area.x + 1,
        y: box_area.y + 1,
        width: box_area.width.saturating_sub(2),
        height: box_area.height.saturating_sub(4),
    };
    if let Some(items) = selector {
        let top = selector_selected(model)
            .unwrap_or(0)
            .saturating_add(2)
            .saturating_sub(body_area.height.saturating_sub(1) as usize) as u16;
        let lines = body
            .lines()
            .enumerate()
            .map(|(line, text)| {
                let style = if line >= 2 && model.hover == Some(MouseTarget::ModalItem(line - 2)) {
                    Style::default().bg(Color::Rgb(70, 75, 85))
                } else {
                    Style::default()
                };
                Line::styled(text.to_owned(), style)
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Left)
                .scroll((top, 0)),
            body_area,
        );
        for index in 0..items.len() {
            let line = index + 2;
            if line >= top as usize && line - (top as usize) < body_area.height as usize {
                hits.add(
                    Rect {
                        x: body_area.x,
                        y: body_area.y + (line - top as usize) as u16,
                        width: body_area.width,
                        height: 1,
                    },
                    MouseTarget::ModalItem(index),
                );
            }
        }
    } else {
        frame.render_widget(
            Paragraph::new(body)
                .alignment(Alignment::Left)
                .scroll((scroll, 0))
                .wrap(Wrap { trim: false }),
            body_area,
        );
    }
    if box_area.height >= 5 {
        let footer = Rect {
            x: box_area.x,
            y: box_area.bottom() - 3,
            width: box_area.width,
            height: 3,
        };
        draw_rows(
            frame,
            footer,
            vec![hotkeys(model, box_area.width < 70)],
            model.hover,
            hits,
        );
    }
}

fn modal_title(mode: &Mode) -> &'static str {
    match mode {
        Mode::FacetCategories { .. } => "Filter · attributes",
        Mode::Properties { .. } => "Properties",
        Mode::FacetValues { .. } => "Filter · values",
        Mode::FacetFirstChoice { .. } => "Choose filter rule",
        Mode::TreeOrder { .. } => "Tree attributes and order",
        Mode::Profiles { .. } => "View profiles",
        Mode::ProfileSave { .. } => "Save view profile",
        Mode::ProfileOverwrite { .. } => "Overwrite view profile",
        Mode::ProfileDelete { .. } => "Delete view profile",
        Mode::Search { .. } => "Search",
        Mode::DeleteConfirm { .. } => "Delete",
        Mode::Edit { .. } => "Edit value",
        Mode::Replace { .. } => "Replace value",
        Mode::GenerateChoice { .. } => "Generate value",
        Mode::BulkGenerateConfirm { .. } => "Generate missing passwords",
        Mode::BulkProgress { .. } => "Generating passwords",
        Mode::GeneratedPreview { .. } => "Generated value",
        Mode::ProviderFailure { .. } => "Provider error",
        Mode::Approval(_) => "Deployment request",
        _ => "Dialog",
    }
}

#[cfg(test)]
mod tests;
