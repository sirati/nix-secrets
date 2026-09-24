use super::*;
use ratatui::layout::{Alignment, Rect};
use ratatui::widgets::{Block, Borders, Clear};

mod text;
use text::{help_text, legend_text, prompt};

pub fn run(rows: Vec<Row>, writer: &mut impl SecretWriter) -> io::Result<()> {
    let mut frontend = CrosstermFrontend::setup()?;
    let result = drive(&mut frontend, writer, &mut Model::new(rows));
    result.and(frontend.restore())
}

struct CrosstermFrontend {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl CrosstermFrontend {
    fn setup() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut output = io::stdout();
        execute!(output, EnterAlternateScreen, event::EnableBracketedPaste)?;
        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(output))?,
        })
    }

    fn restore(&mut self) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            event::DisableBracketedPaste,
            LeaveAlternateScreen
        )?;
        self.terminal.show_cursor()
    }
}

impl Frontend for CrosstermFrontend {
    fn draw(&mut self, model: &Model) -> io::Result<()> {
        self.terminal.draw(|frame| render(frame, model)).map(|_| ())
    }

    fn read(&mut self, timeout: std::time::Duration) -> io::Result<UiEvent> {
        loop {
            if !event::poll(timeout)? {
                return Ok(UiEvent::Tick);
            }
            match event::read()? {
                Event::Resize(_, _) => return Ok(UiEvent::Refresh),
                Event::Paste(value) => return Ok(UiEvent::Paste(value.into_bytes())),
                Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Up => return Ok(UiEvent::Up),
                    KeyCode::Down => return Ok(UiEvent::Down),
                    KeyCode::Enter => return Ok(UiEvent::Enter),
                    KeyCode::Esc => return Ok(UiEvent::Escape),
                    KeyCode::Backspace => return Ok(UiEvent::Backspace),
                    KeyCode::Char(character) => return Ok(UiEvent::Character(character)),
                    _ => {}
                },
                _ => {}
            }
        }
    }
}

fn render(frame: &mut ratatui::Frame<'_>, model: &Model) {
    let area = frame.area();
    let toggle_height = area.height.min(if area.width < 70 { 5 } else { 4 });
    let toggle = Rect {
        height: toggle_height,
        ..area
    };
    let remaining = area.height - toggle_height;
    let legend_height = if remaining >= 7 { 2 } else { 1 }.min(remaining);
    let detail_height = if matches!(model.mode, Mode::Browse) {
        remaining.saturating_sub(legend_height).min(2)
    } else {
        0
    };
    let main_height = remaining - legend_height - detail_height;
    let main = ratatui::layout::Rect {
        y: area.y + toggle_height,
        height: main_height,
        ..area
    };
    let detail = ratatui::layout::Rect {
        y: main.y + main_height,
        height: detail_height,
        ..area
    };
    let legend = ratatui::layout::Rect {
        y: detail.y + detail_height,
        height: legend_height,
        ..area
    };

    frame.render_widget(
        Paragraph::new(toggle_text(model, area.width))
            .block(Block::default().title("View filters").borders(Borders::ALL)),
        toggle,
    );
    if main.height > 0 {
        render_tree(frame, model, main);
    }
    if detail.height > 0 {
        frame.render_widget(
            Paragraph::new(prompt(model)).wrap(Wrap { trim: false }),
            detail,
        );
    }
    if legend.height > 0 {
        frame.render_widget(
            Paragraph::new(legend_text(model, legend.width)).wrap(Wrap { trim: false }),
            legend,
        );
    }
    render_modal(frame, model, area);
}

fn toggle_text(model: &Model, width: u16) -> String {
    fn button(label: &str, selected: bool) -> String {
        if selected {
            format!("<{label}>")
        } else {
            format!("[{label}]")
        }
    }
    let required = button(
        "1 Required",
        model.filter == crate::model::ViewFilter::Required,
    );
    let all = button("2 All", model.filter == crate::model::ViewFilter::All);
    let keys = button("3 Keys", model.filter == crate::model::ViewFilter::Keys);
    let passwords = button(
        "4 Passwords",
        model.filter == crate::model::ViewFilter::Passwords,
    );
    let public = button(
        if width < 70 {
            "5 Public"
        } else {
            "5 Public info"
        },
        model.filter == crate::model::ViewFilter::PublicInfo,
    );
    let everyone = button("6 Everyone", !model.human_only);
    let human = button(
        if width < 70 {
            "7 Human"
        } else {
            "7 Human-facing"
        },
        model.human_only,
    );
    if width < 70 {
        format!("{required} {all} {keys}\n{passwords} {public}\n{everyone} {human}")
    } else {
        format!("{required} {all} {keys} {passwords} {public}\n{everyone} {human}")
    }
}

fn render_modal(frame: &mut ratatui::Frame<'_>, model: &Model, area: Rect) {
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
    let width = area.width.min(80).max(1);
    let inner_width = width.saturating_sub(2).max(1) as usize;
    let lines = body
        .lines()
        .map(|line| line.chars().count().div_ceil(inner_width).max(1))
        .sum::<usize>();
    let height = area.height.min((lines + 2).max(3) as u16);
    let box_area = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, box_area);
    frame.render_widget(
        Paragraph::new(body)
            .block(Block::default().title(title).borders(Borders::ALL))
            .alignment(Alignment::Left)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false }),
        box_area,
    );
}

fn modal_title(mode: &Mode) -> &'static str {
    match mode {
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

fn render_tree(frame: &mut ratatui::Frame<'_>, model: &Model, area: ratatui::layout::Rect) {
    let items = model
        .visible_tree_rows()
        .into_iter()
        .map(|visible| item(&model.rows[visible.index], visible.depth, &visible.label))
        .collect::<Vec<_>>();
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(model.selected));
    let list = List::new(items).highlight_symbol("> ");
    frame.render_stateful_widget(list, area, &mut state);
}

fn item(row: &Row, depth: usize, name: &str) -> ListItem<'static> {
    let indent = "  ".repeat(depth);
    if !row.is_secret() {
        return ListItem::new(format!("{indent}{name}/"));
    }
    let (status, color) = if row.is_set {
        ("set", Color::Green)
    } else {
        ("unset", Color::Red)
    };
    let label = if row.is_task() {
        format!(
            "task · input {status} · output {}",
            row.output_is_set.map(set_status).unwrap_or("unknown")
        )
    } else {
        status.into()
    };
    ListItem::new(Line::from(vec![
        Span::raw(format!("{indent}{name}  ")),
        Span::styled(label, Style::default().fg(color)),
    ]))
}

fn set_status(set: bool) -> &'static str {
    if set {
        "set"
    } else {
        "unset"
    }
}

fn task_status(task: &crate::model::TaskApproval) -> String {
    if task.requires_input {
        format!(
            "{} (bootstrap {}, output {})",
            task.identifier,
            set_status(task.input_is_set),
            task.output_is_set.map(set_status).unwrap_or("unknown")
        )
    } else {
        format!(
            "{} (generated on target; output {})",
            task.identifier,
            task.output_is_set.map(set_status).unwrap_or("unknown")
        )
    }
}

#[cfg(test)]
mod tests;
