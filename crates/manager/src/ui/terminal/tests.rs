use super::*;
use ratatui::backend::TestBackend;
use ratatui::style::Modifier;
use ratatui::Terminal;

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
    model.inform("test result");
    terminal
        .draw(|frame| {
            render(frame, &model);
        })
        .unwrap();
    let screen = (0..8)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(screen.contains("Notice"));
    assert!(screen.contains("test result"));
    assert!(
        screen.contains("(pressing any key will perform its"),
        "{screen}"
    );
    model.acknowledge();
    model.fail("age exited with exit code 1");
    terminal
        .draw(|frame| {
            render(frame, &model);
        })
        .unwrap();
    let screen = (0..8)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(screen.contains("Error"), "{screen}");
    assert!(screen.contains("OK"), "{screen}");
    assert!(!screen.contains("pressing any key"));
    model.message = None;
    model.mode = Mode::Help { scroll: 0 };
    terminal
        .draw(|frame| {
            render(frame, &model);
        })
        .unwrap();
    let screen = (0..8)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(screen.contains("Help"));
}

#[test]
fn wide_terminal_keeps_five_distinct_zones_and_inverse_selected_buttons() {
    let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
    let mut model = Model::new(vec![]);
    terminal
        .draw(|frame| {
            render(frame, &model);
        })
        .unwrap();
    let screen = (0..24)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    for title in ["Filters", "Secrets", "Selected", "Status", "Actions"] {
        assert!(screen.contains(title), "missing zone {title}");
    }
    let zones = regions(terminal.backend().buffer().area, 1);
    assert!(zones.filters.bottom() <= zones.tree.y);
    assert!(zones.tree.bottom() <= zones.selected.y);
    assert!(zones.selected.bottom() <= zones.status.y);
    assert!(zones.status.bottom() <= zones.keys.y);
    assert!(line(&terminal, zones.filters.y + 1).contains("1 Required"));
    assert!(!screen.contains("<1 Required>"));
    assert!(button_reversed(&terminal, "1 Required"));
    assert!(!button_reversed(&terminal, "2 All"));
    model.set_filter(crate::model::ViewFilter::All);
    terminal
        .draw(|frame| {
            render(frame, &model);
        })
        .unwrap();
    assert!(!button_reversed(&terminal, "1 Required"));
    assert!(button_reversed(&terminal, "2 All"));
}

fn button_reversed(terminal: &Terminal<TestBackend>, label: &str) -> bool {
    let buffer = terminal.backend().buffer();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            if buffer[(x, y)].symbol() == &label[..1] {
                let line = line(terminal, y);
                if line.contains(label) {
                    return buffer[(x, y)]
                        .style()
                        .add_modifier
                        .contains(Modifier::REVERSED);
                }
            }
        }
    }
    false
}

#[test]
fn narrow_terminal_retains_distinct_sections_and_all_filters() {
    let mut terminal = Terminal::new(TestBackend::new(40, 20)).unwrap();
    let model = Model::new(vec![]);
    terminal
        .draw(|frame| {
            render(frame, &model);
        })
        .unwrap();
    let screen = (0..20)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    for title in ["Filters", "Secrets", "Selected", "Status", "Actions"] {
        assert!(screen.contains(title), "missing zone {title}");
    }
    for label in [
        "F Filter",
        "T Tree",
        "1 Required",
        "2 All",
        "3 Keys",
        "4 Passwords",
        "5 Public",
        "6 Everyone",
        "7 Human",
    ] {
        assert!(screen.contains(label), "missing button {label}");
    }
    let zones = regions(terminal.backend().buffer().area, 1);
    assert!(zones.filters.bottom() <= zones.tree.y && zones.tree.bottom() <= zones.selected.y);
    assert!(zones.selected.bottom() <= zones.status.y && zones.status.bottom() <= zones.keys.y);
}

#[test]
fn help_and_legend_match_actual_filter_shortcuts() {
    let model = Model::new(vec![]);
    assert!(help_text().contains(
        "1 Required (external values only) · 2 All · 3 Keys · 4 Passwords · 5 Public info"
    ));
    assert!(help_text().contains("6 Everyone · 7 Human-facing"));
    assert!(hotkeys(&model, false)
        .iter()
        .any(|button| button.label == "? Help"));
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
        terminal
            .draw(|frame| {
                render(frame, &model);
            })
            .unwrap();
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

mod mouse;

#[test]
fn activity_overlay_shows_spinner_elapsed_time_and_keeps_screen_clickable() {
    let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
    let mut model = Model::new(vec![]);
    model.activity = Some(crate::model::Activity {
        label: "Decrypting host.services.mail.password".into(),
        waits_for_one_password: true,
        started: std::time::Instant::now() - std::time::Duration::from_secs(7),
    });
    let mut hits = HitMap::default();
    terminal.draw(|frame| hits = render(frame, &model)).unwrap();
    let screen = (0..24)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        screen.contains("Decrypting host.services.mail.password — waiting for 1Password"),
        "{screen}"
    );
    assert!(screen.contains("7s"), "{screen}");
    assert!(hits
        .regions
        .iter()
        .any(|(_, target)| *target == MouseTarget::Busy));
    assert!(
        hits.regions
            .iter()
            .any(|(_, target)| matches!(target, MouseTarget::Shortcut(_))),
        "buttons stay usable while the operation runs"
    );
}
