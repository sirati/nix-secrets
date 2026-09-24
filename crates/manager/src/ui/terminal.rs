use super::*;

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
    let legend_height = if area.height >= 7 { 2 } else { 1 }.min(area.height);
    let status_height = area.height.saturating_sub(legend_height).min(1);
    let detail_height = area
        .height
        .saturating_sub(legend_height + status_height)
        .min(2);
    let main_height = area.height - legend_height - status_height - detail_height;
    let main = ratatui::layout::Rect {
        height: main_height,
        ..area
    };
    let detail = ratatui::layout::Rect {
        y: area.y + main_height,
        height: detail_height,
        ..area
    };
    let status = ratatui::layout::Rect {
        y: detail.y + detail_height,
        height: status_height,
        ..area
    };
    let legend = ratatui::layout::Rect {
        y: status.y + status_height,
        height: legend_height,
        ..area
    };

    if main.height > 0 {
        match &model.mode {
            Mode::Reveal { value, scroll, .. } => {
                let text = std::str::from_utf8(value).unwrap_or("<binary value: use c to copy>");
                frame.render_widget(
                    Paragraph::new(text)
                        .scroll((*scroll, 0))
                        .wrap(Wrap { trim: false }),
                    main,
                );
            }
            Mode::Help { scroll } => {
                frame.render_widget(
                    Paragraph::new(help_text())
                        .scroll((*scroll, 0))
                        .wrap(Wrap { trim: false }),
                    main,
                );
            }
            _ => render_tree(frame, model, main),
        }
    }
    if detail.height > 0 {
        frame.render_widget(
            Paragraph::new(prompt(model)).wrap(Wrap { trim: false }),
            detail,
        );
    }
    if status.height > 0 {
        frame.render_widget(
            Paragraph::new(format!(
                "Status: {}",
                model.message.as_deref().unwrap_or("ready")
            )),
            status,
        );
    }
    if legend.height > 0 {
        frame.render_widget(
            Paragraph::new(legend_text(model, legend.width)).wrap(Wrap { trim: false }),
            legend,
        );
    }
}

fn render_tree(frame: &mut ratatui::Frame<'_>, model: &Model, area: ratatui::layout::Rect) {
    let items = model
        .visible_rows()
        .into_iter()
        .map(|index| item(&model.rows[index]))
        .collect::<Vec<_>>();
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(model.selected));
    let list = List::new(items).highlight_symbol("> ");
    frame.render_stateful_widget(list, area, &mut state);
}

fn prompt(model: &Model) -> String {
    match &model.mode {
        Mode::Browse => {
            let description = model
                .selected()
                .and_then(|row| row.description.as_deref())
                .unwrap_or("");
            format!(
                "Selected: {}\n{} · type: {} · audience: {}",
                model
                    .selected()
                    .map(|row| row.path.as_deref().unwrap_or(&row.name))
                    .unwrap_or("none"),
                description,
                model.filter.name(),
                if model.human_only { "human" } else { "all" }
            )
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

fn legend_text(model: &Model, width: u16) -> String {
    if width < 45 {
        return match model.mode {
            Mode::Browse => "↑↓ move · Enter edit · ? help".into(),
            Mode::Help { .. } => "↑↓ scroll · Esc close".into(),
            Mode::Reveal { .. } => "↑↓ scroll · c copy · Esc hide".into(),
            _ => "Enter accept · Esc cancel · ? help from browse".into(),
        };
    }
    match model.mode {
        Mode::Browse => "Navigate: ↑↓ move · / search · f type · h audience · ? help\nValues: Enter edit · paste set · g generate · r reveal · c copy · p public · d delete · Esc quit".into(),
        Mode::Help { .. } => "Help: ↑↓ scroll · Esc or ? close".into(),
        Mode::Reveal { .. } => "Reveal: ↑↓ scroll · c copy · Enter or Esc hide".into(),
        Mode::Search { .. } => "Search: type query · Backspace erase · Enter keep · Esc clear".into(),
        Mode::Approval(_) => "Deployment: y approve · n reject · Esc reject".into(),
        Mode::DeleteConfirm { .. } | Mode::Replace { .. } => "Confirm: y proceed · n cancel · Esc cancel".into(),
        Mode::GenerateChoice { .. } => "Generate: p password · w passphrase · Esc cancel".into(),
        Mode::GeneratedPreview { .. } => "Preview: r reveal · c copy · Enter save · Esc discard".into(),
        Mode::ProviderFailure { .. } => "Provider: r retry · Esc cancel".into(),
        Mode::Edit { .. } => "Edit: type or paste · Backspace erase · Enter save · Esc cancel".into(),
    }
}

fn help_text() -> &'static str {
    "NAVIGATE\n↑ / ↓  Move between visible items\n/  Search names, identifiers, and descriptions\nf  Cycle all, private keys, passwords, and public info\nh  Toggle human-facing items\n?  Show or close this help\n\nEDIT\nEnter  Edit selected value; Enter again saves\nPaste  Set from clipboard; replacement asks first\ng  Generate password or passphrase for a password field\nr  Reveal selected value\nc  Copy the selected value\np  Copy the public half of a stored OpenSSH private key\nd  Delete selected value after confirmation\n\nDEPLOYMENT\nA target deployer requests one server's values.\ny  Approve the verified target and displayed changes\nn / Esc  Reject the request\n\nEsc  Leave a view, or quit from the tree"
}

fn item(row: &Row) -> ListItem<'static> {
    let indent = "  ".repeat(row.depth);
    if !row.is_secret() {
        return ListItem::new(format!("{indent}{}/", row.name));
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
        Span::raw(format!("{indent}{}  ", row.name)),
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
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn line(terminal: &Terminal<TestBackend>, y: u16) -> String {
        let buffer = terminal.backend().buffer();
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect::<String>()
    }

    #[test]
    fn compact_footer_keeps_status_and_hotkeys_on_separate_rows() {
        let mut terminal = Terminal::new(TestBackend::new(40, 5)).unwrap();
        let mut model = Model::new(vec![]);
        model.message = Some("test result".into());
        terminal.draw(|frame| render(frame, &model)).unwrap();
        assert!(line(&terminal, 3).contains("Status: test result"));
        assert!(line(&terminal, 4).contains("? help"));
        model.mode = Mode::Help { scroll: 0 };
        terminal.draw(|frame| render(frame, &model)).unwrap();
        assert!(line(&terminal, 3).contains("Status: test result"));
        assert!(line(&terminal, 4).contains("Esc close"));
    }

    #[test]
    fn wide_footer_keeps_both_legend_lines_below_status() {
        let mut terminal = Terminal::new(TestBackend::new(100, 12)).unwrap();
        let mut model = Model::new(vec![]);
        model.message = Some("copied".into());
        terminal.draw(|frame| render(frame, &model)).unwrap();
        assert!(line(&terminal, 9).contains("Status: copied"));
        assert!(line(&terminal, 10).contains("Navigate:"));
        assert!(line(&terminal, 11).contains("Values:"));
    }
}
