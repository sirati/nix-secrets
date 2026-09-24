use super::*;
use ratatui::backend::TestBackend;

fn line(terminal: &Terminal<TestBackend>, y: u16) -> String {
    let buffer = terminal.backend().buffer();
    (0..buffer.area.width)
        .map(|x| buffer[(x, y)].symbol())
        .collect::<String>()
}

#[test]
fn compact_terminal_renders_notice_modal_and_filter_bar() {
    let mut terminal = Terminal::new(TestBackend::new(40, 8)).unwrap();
    let mut model = Model::new(vec![]);
    model.message = Some("test result".into());
    terminal.draw(|frame| render(frame, &model)).unwrap();
    let screen = (0..8)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(screen.contains("Notice"));
    assert!(screen.contains("test result"));
    assert!(screen.contains("Enter: continue"));
    model.message = None;
    model.mode = Mode::Help { scroll: 0 };
    terminal.draw(|frame| render(frame, &model)).unwrap();
    let screen = (0..8)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(screen.contains("Help"));
}

#[test]
fn wide_terminal_keeps_filter_bar_and_legend_behind_modal() {
    let mut terminal = Terminal::new(TestBackend::new(100, 12)).unwrap();
    let mut model = Model::new(vec![]);
    model.message = Some("copied".into());
    terminal.draw(|frame| render(frame, &model)).unwrap();
    let screen = (0..12)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(screen.contains("Notice"));
    assert!(screen.contains("copied"));
    assert!(screen.contains("<1 Required>"));
    assert!(line(&terminal, 10).contains("Navigate:"));
    assert!(line(&terminal, 11).contains("Values:"));
}

#[test]
fn provider_error_modal_redacts_pending_secret_and_tiny_terminals_do_not_panic() {
    let mut model = Model::new(vec![]);
    model.mode = Mode::ProviderFailure {
        message: "provider unavailable".into(),
        path: "host.services.mail.password".into(),
        value: Zeroizing::new(b"do-not-render-me".to_vec()),
    };
    for (width, height) in [(1, 1), (12, 4), (40, 8)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, &model)).unwrap();
        let screen = (0..height)
            .map(|y| line(&terminal, y))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!screen.contains("do-not-render-me"));
        if width == 40 {
            assert!(screen.contains("Provider error"));
        }
    }
}
