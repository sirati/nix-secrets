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

    fn read(&mut self) -> io::Result<UiEvent> {
        loop {
            if !event::poll(std::time::Duration::from_millis(250))? {
                return Ok(UiEvent::Tick);
            }
            match event::read()? {
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
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(4)])
        .split(frame.area());
    let items = model.rows.iter().map(item).collect::<Vec<_>>();
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(model.selected));
    let list = List::new(items)
        .block(Block::default().title("Secrets").borders(Borders::ALL))
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, areas[0], &mut state);
    frame.render_widget(
        Paragraph::new(prompt(model))
            .block(Block::default().title("Action").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        areas[1],
    );
}

fn prompt(model: &Model) -> String {
    match &model.mode {
        Mode::Browse => model.message.clone().unwrap_or_else(|| {
            "Enter: edit · paste: set · d: deploy selected set secret · Esc: quit".into()
        }),
        Mode::Edit { value, .. } => format!(
            "value: {}  (Enter saves, Esc cancels)",
            "•".repeat(value.len())
        ),
        Mode::Replace { path, .. } => format!("Replace {path}? y/n"),
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
                    "{failure} Deploy to {}? create [{}], replace [{}], keys [{}] · y/n",
                    request.target,
                    request.create.join(", "),
                    request.replace.join(", "),
                    request.recipient_keys.join(", ")
                )
            }
        }
    }
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
    ListItem::new(Line::from(vec![
        Span::raw(format!("{indent}{}  ", row.name)),
        Span::styled(status, Style::default().fg(color)),
    ]))
}
