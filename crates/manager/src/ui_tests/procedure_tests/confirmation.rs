//! `nix-secrets procedure-confirm` in the TUI: a red warning that only y
//! confirms, n and Esc decline, nothing else answers, and that does not
//! count towards the procedure's declared steps.
use super::*;
use nix_secrets_core::procedure::Confirmation;
use ratatui::style::Color;

const LABEL: &str = "deployed from a dirty tree";

/// A confirmation of `UPDATE`, asked about its current step `number`.
fn confirmation(id: &str, number: u32, items: usize) -> SecretPrompt {
    let mut prompt = prompt(id, Some(step(UPDATE, "Update ns1", number, LABEL)));
    prompt.values.clear();
    prompt.ssh_signature = false;
    prompt.deadline = None;
    prompt.confirmation = Some(Confirmation {
        label: LABEL.into(),
        reason: "the operator's tree has uncommitted changes".into(),
        items: (0..items)
            .map(|item| format!("M file-{item}.nix"))
            .collect(),
    });
    prompt
}

fn answered(model: &mut Model, id: &str, result: Result<(), String>) {
    crate::ui::apply_completion_for_tests(
        model,
        crate::ui::Completion::ConfirmationFinished {
            id: id.into(),
            requester: "nix-update-remote (pid 42)".into(),
            result,
        },
    );
}

/// The screen and the colour of the first cell of `needle` on it.
fn colour_of(model: &Model, needle: &str) -> Option<Color> {
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 45)).unwrap();
    crate::ui::render_for_tests(&mut terminal, model);
    let cells = terminal.backend().buffer().content();
    // The screen as text, and which cell each byte of it came from.
    let (mut text, mut owner) = (String::new(), Vec::new());
    for (index, cell) in cells.iter().enumerate() {
        text.push_str(cell.symbol());
        owner.resize(text.len(), index);
    }
    let at = text.find(needle)?;
    Some(cells[owner[at]].fg)
}

#[test]
fn only_y_confirms_and_the_warning_is_red_with_its_items() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(confirmation("confirm", 0, 3));
    tick(&mut model, &mut channel);
    assert!(model.shown_prompt().is_some());
    let screen = render(&model);
    assert!(
        screen.contains(&format!("WARNING · Update ns1 · confirm: {LABEL}")),
        "{screen}"
    );
    assert!(screen.contains("uncommitted changes"), "{screen}");
    assert!(screen.contains("3 items:"), "{screen}");
    for item in ["M file-0.nix", "M file-1.nix", "M file-2.nix"] {
        assert!(screen.contains(item), "{screen}");
    }
    assert!(screen.contains("y Yes, confirm"), "{screen}");
    assert!(
        !screen.contains("denies in"),
        "it never counts down: {screen}"
    );
    assert_eq!(colour_of(&model, "WARNING"), Some(Color::Red));
    assert_eq!(
        colour_of(&model, "┌ WARNING"),
        Some(Color::Red),
        "the border is red"
    );
    // Nothing else answers it: not Enter, not the approval chord, not Y.
    for event in [
        UiEvent::Enter,
        UiEvent::ConfirmLoss,
        UiEvent::Character('Y'),
        UiEvent::Character('a'),
        UiEvent::Character('d'),
        UiEvent::Character('c'),
        UiEvent::Character(' '),
        UiEvent::Tab,
        UiEvent::Tick,
        UiEvent::Click(MouseTarget::ConfirmLoss),
        UiEvent::Click(MouseTarget::Shortcut(Shortcut::Enter)),
    ] {
        reduce(&mut model, event, &mut channel);
        assert!(channel.answers.is_empty());
        assert!(model.shown_prompt().is_some());
    }
    // Long past any countdown, it still waits.
    tick(&mut model, &mut channel);
    model.expire_prompts(Instant::now() + Duration::from_secs(3600));
    assert!(model.shown_prompt().is_some());
    reduce(&mut model, UiEvent::Character('y'), &mut channel);
    assert_eq!(channel.answers, [("confirm".to_owned(), true)]);
    assert!(model.shown_prompt().is_none());
    answered(&mut model, "confirm", Ok(()));
    let screen = render(&model);
    assert!(
        screen.contains(&format!("⚠ {LABEL}: confirmed")),
        "{screen}"
    );
    assert!(screen.contains("waiting for step 1/3"), "{screen}");
}

#[test]
fn n_and_esc_decline_and_the_step_is_listed_as_denied() {
    for key in [UiEvent::Character('n'), UiEvent::Escape] {
        let mut model = model(true);
        let mut channel = Channel::default();
        channel.prompts.push(confirmation("confirm", 0, 1));
        tick(&mut model, &mut channel);
        reduce(&mut model, key, &mut channel);
        assert_eq!(channel.answers, [("confirm".to_owned(), false)]);
        answered(&mut model, "confirm", Err("the operator declined".into()));
        let screen = render(&model);
        assert!(
            screen.contains(&format!("✗ {LABEL}: the operator declined")),
            "{screen}"
        );
        assert!(screen.contains(&format!("denied: {LABEL}")), "{screen}");
        assert!(!screen.contains("step 0"), "{screen}");
    }
}

#[test]
fn a_long_item_list_is_cut_and_scrolls() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(confirmation("confirm", 0, 55));
    tick(&mut model, &mut channel);
    let body = crate::ui::secret_request::confirmation_body(model.shown_prompt().unwrap());
    assert!(body.contains("55 items:"), "{body}");
    assert!(body.contains("M file-39.nix"), "{body}");
    assert!(!body.contains("M file-40.nix"), "{body}");
    assert!(body.contains("+15 more"), "{body}");
    let screen = render(&model);
    assert!(screen.contains("more lines below"), "{screen}");
    reduce(&mut model, UiEvent::Down, &mut channel);
    assert_eq!(model.secret_scroll, 1);
    assert!(channel.answers.is_empty(), "scrolling never answers");
}

/// The updater declares three steps and confirms a dirty tree before the
/// first: the confirmation does not count, and all three steps finish as
/// 3 of 3.
#[test]
fn a_confirmation_does_not_count_towards_the_declared_steps() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.events.push(ProcedureEvent::Step(step(
        UPDATE,
        "Update ns1",
        0,
        "starting",
    )));
    channel.prompts.push(confirmation("confirm", 0, 2));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::Character('y'), &mut channel);
    answered(&mut model, "confirm", Ok(()));
    assert!(render(&model).contains("waiting for step 1/3"));
    for number in 1..=3 {
        let id = format!("closure-{number}");
        channel.prompts.push(closure_step(&id, number, 3));
        tick(&mut model, &mut channel);
        reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
        signed(&mut model, &id, Ok(()));
    }
    let screen = render(&model);
    for line in [
        "✓ step 1/3",
        "✓ step 2/3",
        "✓ step 3/3",
        "All steps are done.",
    ] {
        assert!(screen.contains(line), "{screen}");
    }
    assert!(
        screen.contains("Update ns1 · succeeded with warnings"),
        "{screen}"
    );
    assert!(!screen.contains("step 4"), "{screen}");
    let procedure = model.procedure(UPDATE).unwrap();
    assert_eq!(procedure.missed(), None);
    assert_eq!(procedure.warnings().count(), 1);
    channel
        .events
        .push(ProcedureEvent::Ended(UPDATE.into(), Some(0)));
    tick(&mut model, &mut channel);
    let screen = render(&model);
    assert!(!screen.contains("ended early"), "{screen}");
    assert!(screen.contains("succeeded with warnings"), "{screen}");
}
