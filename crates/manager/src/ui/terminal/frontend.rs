use super::*;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::Stdout;

pub(super) struct CrosstermFrontend {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    hits: HitMap,
    /// When the last Ctrl+V was accepted. Terminals send held keys as fresh
    /// presses, so repeats within [`PASTE_REPEAT_GAP`] are dropped and holding
    /// Ctrl+V reads the clipboard once.
    last_paste: Option<std::time::Instant>,
}

const PASTE_REPEAT_GAP: std::time::Duration = std::time::Duration::from_millis(400);

impl CrosstermFrontend {
    pub(super) fn setup() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut output = io::stdout();
        execute!(
            output,
            EnterAlternateScreen,
            event::EnableBracketedPaste,
            event::EnableMouseCapture
        )?;
        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(output))?,
            hits: HitMap::default(),
            last_paste: None,
        })
    }

    pub(super) fn restore(&mut self) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            event::DisableBracketedPaste,
            event::DisableMouseCapture,
            LeaveAlternateScreen
        )?;
        self.terminal.show_cursor()
    }
}

impl Frontend for CrosstermFrontend {
    fn draw(&mut self, model: &Model) -> io::Result<()> {
        self.terminal
            .draw(|frame| self.hits = render(frame, model))
            .map(|_| ())
    }

    fn edit(&mut self, text: &str) -> Result<String, String> {
        // The editor gets the real terminal: leave raw mode and the alternate
        // screen, and come back afterwards whatever the editor did.
        self.restore().map_err(|error| error.to_string())?;
        let edited = crate::editor::edit_with(&crate::editor::command(), text);
        let resumed = enable_raw_mode().and_then(|()| {
            execute!(
                self.terminal.backend_mut(),
                EnterAlternateScreen,
                event::EnableBracketedPaste,
                event::EnableMouseCapture
            )
        });
        let _ = self.terminal.clear();
        resumed.map_err(|error| format!("cannot restore the terminal: {error}"))?;
        edited
    }

    fn read(&mut self, timeout: std::time::Duration) -> io::Result<UiEvent> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if !event::poll(deadline.saturating_duration_since(std::time::Instant::now()))? {
                return Ok(UiEvent::Tick);
            }
            match event::read()? {
                Event::Resize(_, _) => return Ok(UiEvent::Refresh),
                Event::Paste(value) => return Ok(UiEvent::Paste(value.into_bytes())),
                Event::Mouse(mouse) => match mouse.kind {
                    event::MouseEventKind::Moved => {
                        return Ok(UiEvent::Hover(self.hits.get(mouse.column, mouse.row)))
                    }
                    event::MouseEventKind::Down(event::MouseButton::Left) => {
                        if let Some(target) = self.hits.get(mouse.column, mouse.row) {
                            return Ok(UiEvent::Click(target));
                        }
                    }
                    event::MouseEventKind::ScrollUp => return Ok(UiEvent::Up),
                    event::MouseEventKind::ScrollDown => return Ok(UiEvent::Down),
                    _ => {}
                },
                Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Up => return Ok(UiEvent::Up),
                    KeyCode::Down => return Ok(UiEvent::Down),
                    KeyCode::Enter => return Ok(UiEvent::Enter),
                    KeyCode::Esc => return Ok(UiEvent::Escape),
                    KeyCode::Backspace => return Ok(UiEvent::Backspace),
                    KeyCode::Tab => return Ok(UiEvent::Tab),
                    // Terminals differ: some report Ctrl+Shift+Y as Ctrl with an
                    // uppercase Y, others add SHIFT to a lowercase y. Plain y and
                    // Ctrl+y without Shift never confirm.
                    KeyCode::Char(character @ ('y' | 'Y'))
                        if key.modifiers.contains(event::KeyModifiers::CONTROL)
                            && (character == 'Y'
                                || key.modifiers.contains(event::KeyModifiers::SHIFT)) =>
                    {
                        return Ok(UiEvent::ConfirmLoss)
                    }
                    KeyCode::Char('r' | 'R')
                        if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                    {
                        return Ok(UiEvent::RevealCurrent)
                    }
                    KeyCode::Char('v' | 'V')
                        if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                    {
                        let now = std::time::Instant::now();
                        let repeat = self
                            .last_paste
                            .is_some_and(|last| now.duration_since(last) < PASTE_REPEAT_GAP);
                        self.last_paste = Some(now);
                        if !repeat {
                            return Ok(UiEvent::PasteRequest);
                        }
                    }
                    KeyCode::Char('s' | 'S')
                        if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                    {
                        return Ok(UiEvent::Submit)
                    }
                    KeyCode::Char('o' | 'O')
                        if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                    {
                        return Ok(UiEvent::ToggleSignoff)
                    }
                    KeyCode::Char('e' | 'E')
                        if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                    {
                        return Ok(UiEvent::OpenEditor)
                    }
                    KeyCode::Char(_) if key.modifiers.contains(event::KeyModifiers::CONTROL) => {}
                    KeyCode::Char(character) => return Ok(UiEvent::Character(character)),
                    _ => {}
                },
                _ => {}
            }
        }
    }
}
