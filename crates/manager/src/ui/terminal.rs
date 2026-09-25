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
use crate::model::NoticeSeverity;
use actions::hotkeys;
use buttons::{draw_rows, wrap_buttons, Button};
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
        let status = if model
            .message
            .as_ref()
            .is_some_and(|notice| notice.severity == NoticeSeverity::Failure)
        {
            "Error pending · Enter or OK closes it".to_owned()
        } else if matches!(model.mode, Mode::BulkProgress { .. }) {
            "Generating passwords".to_owned()
        } else if let Some(summary) = model.search_summary() {
            format!("Search \"{}\": {}", model.search, summary.text())
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
    render_activity(frame, model, area, &mut hits);
    hits
}

const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub(super) fn activity_text(activity: &crate::model::Activity) -> String {
    let elapsed = activity.started.elapsed();
    let frame = SPINNER[(elapsed.as_millis() / 100) as usize % SPINNER.len()];
    let waiting = if activity.waits_for_one_password {
        " — waiting for 1Password approval if prompted"
    } else {
        ""
    };
    format!(
        "{frame} {}{waiting}… {}s",
        activity.label,
        elapsed.as_secs()
    )
}

/// A progress strip at the top that leaves the rest of the screen usable.
fn render_activity(frame: &mut ratatui::Frame<'_>, model: &Model, area: Rect, hits: &mut HitMap) {
    let Some(activity) = &model.activity else {
        return;
    };
    if area.height < 3 || area.width < 4 {
        return;
    }
    let text = activity_text(activity);
    let width = area.width.min(90);
    let inner = width.saturating_sub(2).max(1) as usize;
    let lines = text.chars().count().div_ceil(inner).clamp(1, 3) as u16;
    let strip = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y,
        width,
        height: (lines + 2).min(area.height),
    };
    frame.render_widget(Clear, strip);
    frame.render_widget(
        Paragraph::new(text)
            .style(Style::default().fg(Color::Yellow))
            .wrap(Wrap { trim: false })
            .block(Block::default().title("Working").borders(Borders::ALL)),
        strip,
    );
    hits.add(strip, MouseTarget::Busy);
}

fn render_modal(frame: &mut ratatui::Frame<'_>, model: &Model, area: Rect, hits: &mut HitMap) {
    match &model.message {
        Some(notice)
            if notice.severity == NoticeSeverity::Failure
                || !super::prelude::passes_through(&model.mode) =>
        {
            let failure = notice.severity == NoticeSeverity::Failure;
            draw_dialog(
                frame,
                model,
                area,
                hits,
                Dialog {
                    title: if failure { "Error" } else { "Notice" },
                    body: if failure {
                        format!("{}\n\n↑↓: scroll · Enter or OK: close", notice.text)
                    } else {
                        // A key never reaches a confirmation or entry dialog below.
                        format!("{}\n\n(press any key to close this)", notice.text)
                    },
                    scroll: model.modal_scroll,
                    selector: None,
                    footer: failure.then(|| hotkeys(model, area.width < 70)),
                    exclusive: true,
                },
            );
            if !failure {
                hits.add(area, MouseTarget::Notice);
            }
        }
        Some(notice) => {
            // The screen underneath stays live: its hit regions remain so a
            // click closes the notice and then acts on what it hit.
            render_mode_modal(frame, model, area, hits);
            let dialog = draw_dialog(
                frame,
                model,
                area,
                hits,
                Dialog {
                    title: "Notice",
                    body: format!("{}\n\n{INFO_NOTICE_HINT}", notice.text),
                    scroll: 0,
                    selector: None,
                    footer: None,
                    exclusive: false,
                },
            );
            hits.add(dialog, MouseTarget::Notice);
        }
        None => render_mode_modal(frame, model, area, hits),
    }
}

pub(super) const INFO_NOTICE_HINT: &str =
    "(pressing any key will perform its usual action and close this)";

fn render_mode_modal(frame: &mut ratatui::Frame<'_>, model: &Model, area: Rect, hits: &mut HitMap) {
    let (title, body, scroll) = match &model.mode {
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
    };
    draw_dialog(
        frame,
        model,
        area,
        hits,
        Dialog {
            title,
            body,
            scroll,
            selector: selector_items(model),
            footer: Some(hotkeys(model, area.width < 70)),
            exclusive: true,
        },
    );
}

struct Dialog {
    title: &'static str,
    body: String,
    scroll: u16,
    selector: Option<Vec<String>>,
    footer: Option<Vec<Button>>,
    /// Whether the dialog replaces every hit region beneath it.
    exclusive: bool,
}

fn draw_dialog(
    frame: &mut ratatui::Frame<'_>,
    model: &Model,
    area: Rect,
    hits: &mut HitMap,
    dialog: Dialog,
) -> Rect {
    if area.width == 0 || area.height == 0 {
        return Rect::default();
    }
    if dialog.exclusive {
        hits.regions.clear();
    }
    let body = dialog.body;
    let width = area.width.min(80).max(1);
    let inner_width = width.saturating_sub(2).max(1) as usize;
    let lines = if dialog.selector.is_some() {
        body.lines().count()
    } else {
        // Counts the lines exactly as the wrapped paragraph renders them.
        Paragraph::new(body.as_str())
            .wrap(Wrap { trim: false })
            .line_count(inner_width as u16)
    };
    let chrome = if dialog.footer.is_some() { 4 } else { 2 };
    let height = area.height.min((lines + chrome).max(chrome + 1) as u16);
    let box_area = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, box_area);
    frame.render_widget(
        Block::default().title(dialog.title).borders(Borders::ALL),
        box_area,
    );
    let body_area = Rect {
        x: box_area.x + 1,
        y: box_area.y + 1,
        width: box_area.width.saturating_sub(2),
        height: box_area.height.saturating_sub(chrome as u16),
    };
    if let Some(items) = dialog.selector {
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
        // Scrolling stops once the last line is at the bottom of the box.
        let limit = lines
            .saturating_sub(body_area.height as usize)
            .min(u16::MAX as usize) as u16;
        if dialog.exclusive {
            model.scroll_limit.set(limit);
        }
        frame.render_widget(
            Paragraph::new(body)
                .alignment(Alignment::Left)
                .scroll((dialog.scroll.min(limit), 0))
                .wrap(Wrap { trim: false }),
            body_area,
        );
    }
    if let Some(buttons) = dialog.footer {
        if box_area.height >= 5 {
            let footer = Rect {
                x: box_area.x,
                y: box_area.bottom() - 3,
                width: box_area.width,
                height: 3,
            };
            draw_rows(frame, footer, vec![buttons], model.hover, hits);
        }
    }
    box_area
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
