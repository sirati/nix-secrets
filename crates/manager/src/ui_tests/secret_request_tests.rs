//! The secret-request modal: above every dialog, only Ctrl+Shift+Y sends,
//! n/Enter/Esc deny, it expires, and the dialog underneath survives.
use super::*;
use crate::operator_channel::SecretPrompt;
use crate::secret_values::RequestedValue;
use nix_secrets_core::secret_request::ProcessInfo;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Requests {
    prompts: Vec<SecretPrompt>,
    answers: Vec<(String, bool)>,
    writes: usize,
}

impl SecretWriter for Requests {
    fn write(
        &mut self,
        path: &str,
        _value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        self.writes += 1;
        Ok(Action::Saved(path.into()))
    }
    fn poll_secret_prompt(&mut self) -> Option<SecretPrompt> {
        (!self.prompts.is_empty()).then(|| self.prompts.remove(0))
    }
    fn answer_secret(&mut self, id: &str, approved: bool, _count: usize) -> Result<(), String> {
        self.answers.push((id.into(), approved));
        Ok(())
    }
}

fn prompt(id: &str, deadline: Instant) -> SecretPrompt {
    let process = |pid, argv: &[&str]| ProcessInfo {
        pid,
        executable: Some(format!("/bin/{}", argv[0])),
        argv: argv.iter().map(|argument| argument.to_string()).collect(),
        cwd: Some("/home/op/config".into()),
    };
    SecretPrompt {
        id: id.into(),
        values: vec![RequestedValue {
            identifier: "host.services.nmbl.generation-key".into(),
            kind: "operator key".into(),
            description: Some("NMBL generation signing key".into()),
            recipients: vec!["primary: ssh-ed25519 SHA256:abc".into()],
        }],
        identity: "1Password on this machine".into(),
        requester: process(42, &["nix-secrets", "with-secrets"]),
        parent: Some(process(41, &["nmbl-install", "--target", "dns-vps"])),
        deadline,
    }
}

/// Runs the drive loop over `events`, then quits.
fn drive_with(model: &mut Model, writer: &mut Requests, events: Vec<UiEvent>) {
    let mut frontend = FakeFrontend {
        events: events.into_iter().chain([UiEvent::Tick]).collect(),
        draws: 0,
    };
    frontend.events.push_back(UiEvent::Escape);
    frontend.events.push_back(UiEvent::Escape);
    frontend.events.push_back(UiEvent::Escape);
    let _ = drive(&mut frontend, writer, model);
}

#[test]
fn a_request_opens_over_an_open_dialog_and_leaves_it_intact() {
    let mut model = model(true);
    let mut writer = Requests::default();
    // An entry dialog with typed text is open.
    reduce(&mut model, UiEvent::Enter, &mut writer);
    reduce(&mut model, UiEvent::Character('x'), &mut writer);
    writer
        .prompts
        .push(prompt("r1", Instant::now() + Duration::from_secs(120)));
    crate::ui::secret_request_tick_for_tests(&mut model, &mut writer);
    assert!(model.secret_prompt.is_some());
    // Typing, Enter-to-save and paste never reach the entry dialog below.
    reduce(&mut model, UiEvent::Character('y'), &mut writer);
    reduce(&mut model, UiEvent::Paste(b"pasted".to_vec()), &mut writer);
    assert!(model.secret_prompt.is_some(), "y alone never answers");
    assert!(writer.answers.is_empty());
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert_eq!(writer.answers, [("r1".to_owned(), false)], "Enter denies");
    assert_eq!(writer.writes, 0);
    assert!(model.secret_prompt.is_none());
    match &model.mode {
        Mode::Edit { value, .. } => assert_eq!(value.as_slice(), b"x"),
        other => panic!("the entry dialog was lost: {other:?}"),
    }
}

#[test]
fn only_the_strong_key_or_the_yes_button_sends() {
    for (event, approved) in [
        (UiEvent::ConfirmLoss, true),
        (UiEvent::Click(MouseTarget::ConfirmLoss), true),
        (UiEvent::Character('n'), false),
        (UiEvent::Escape, false),
        (UiEvent::Enter, false),
        (
            UiEvent::Click(MouseTarget::Shortcut(Shortcut::Escape)),
            false,
        ),
    ] {
        let mut model = model(true);
        let mut writer = Requests::default();
        model.fail("an earlier error is still open");
        writer
            .prompts
            .push(prompt("r", Instant::now() + Duration::from_secs(120)));
        crate::ui::secret_request_tick_for_tests(&mut model, &mut writer);
        let description = format!("{event:?}");
        reduce(&mut model, event, &mut writer);
        assert_eq!(
            writer.answers,
            [("r".to_owned(), approved)],
            "{description}"
        );
        // The notice underneath is still there afterwards.
        assert_eq!(model.message_text(), Some("an earlier error is still open"));
    }
}

#[test]
fn the_request_expires_and_the_outcome_names_the_requester() {
    let mut model = model(true);
    let mut writer = Requests::default();
    writer.prompts.push(prompt("r", Instant::now()));
    drive_with(&mut model, &mut writer, vec![UiEvent::Tick]);
    assert!(model.secret_prompt.is_none(), "expired requests close");
    assert!(writer.answers.is_empty(), "the channel denies on its own");
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::SecretRequestFinished {
            requester: "nmbl-install (PID 41)".into(),
            result: Ok(1),
        },
    );
    assert_eq!(
        model.message_text(),
        Some("Sent 1 secret value to nmbl-install (PID 41).")
    );
    model.acknowledge();
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::SecretRequestFinished {
            requester: "nmbl-install (PID 41)".into(),
            result: Err("the operator denied the secret request".into()),
        },
    );
    assert!(model
        .message_text()
        .is_some_and(|text| text.contains("nmbl-install (PID 41)") && text.contains("denied")));
}

const FINGERPRINT: &str = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

/// A request with two values, a long description and a long command.
fn detailed_prompt() -> SecretPrompt {
    let mut prompt = prompt("r", Instant::now() + Duration::from_secs(90));
    let recipient = format!("primary: ssh-ed25519 {FINGERPRINT}");
    prompt.values = vec![
        RequestedValue {
            identifier: "host.services.nmbl.generation-key".into(),
            kind: "operator key".into(),
            description: Some(
                "NMBL generation signing key; it signs every boot generation of dns-vps".into(),
            ),
            recipients: vec![recipient.clone()],
        },
        RequestedValue {
            identifier: "host.services.storage-box.password".into(),
            kind: "secret".into(),
            description: None,
            recipients: vec![recipient],
        },
    ];
    prompt.requester.argv = [
        "nix-secrets",
        "with-secrets",
        "host.services.nmbl.generation-key",
        "host.services.storage-box.password",
        "--",
        "nmbl-install",
        "--target",
        "dns-vps",
        "--generation-key-command",
        "nix-secrets pipe-secret host.services.nmbl.generation-key",
    ]
    .map(String::from)
    .to_vec();
    prompt
}

/// The modal's box on a rendered screen: left, top, right and bottom.
fn modal_box(screen: &str) -> (usize, usize, usize, usize) {
    let rows: Vec<Vec<char>> = screen.lines().map(|line| line.chars().collect()).collect();
    let top = rows
        .iter()
        .position(|row| {
            row.iter()
                .collect::<String>()
                .contains("Secret request from")
        })
        .expect("the modal title is shown");
    let title = rows[top].iter().collect::<String>();
    let at = title.find("Secret request from").unwrap();
    let left = title[..at].chars().count() - 1;
    assert_eq!(rows[top][left], '┌', "{screen}");
    let right = (left + 1..rows[top].len())
        .find(|&x| rows[top][x] == '┐')
        .expect("the top right corner");
    let bottom = (top + 1..rows.len())
        .find(|&y| rows[y][left] == '└')
        .expect("the bottom left corner");
    assert_eq!(rows[bottom][right], '┘', "{screen}");
    for row in &rows[top + 1..bottom] {
        assert_eq!(row[left], '│', "{screen}");
        assert_eq!(row[right], '│', "{screen}");
    }
    (left, top, right, bottom)
}

fn render(model: &Model, width: u16, height: u16) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    crate::ui::render_for_tests(&mut terminal, model)
}

#[test]
fn the_modal_summarises_the_request_in_about_4_to_3_at_every_size() {
    let mut model = model(true);
    model.secret_prompt = Some(detailed_prompt());
    for (width, height, aspect) in [
        (200, 60, true),
        (120, 40, true),
        (80, 24, false),
        (60, 20, false),
    ] {
        let screen = render(&model, width, height);
        let (left, top, right, bottom) = modal_box(&screen);
        let (box_width, box_height) = (right - left + 1, bottom - top + 1);
        let size = format!("{width}x{height}: box {box_width}x{box_height}\n{screen}");
        // It fits the screen and keeps a margin where there is room.
        assert!(right < width as usize && bottom < height as usize, "{size}");
        if width >= 80 {
            assert!(left >= 2 && right + 2 < width as usize, "{size}");
            assert!(top >= 1 && bottom + 1 < height as usize, "{size}");
        } else {
            assert_eq!(box_width, width as usize, "narrow screens use every column");
        }
        if aspect {
            // Cells are about twice as tall as wide: 4:3 is about 8:3.
            let ratio = box_width as f64 / box_height as f64;
            assert!((2.3..=3.0).contains(&ratio), "aspect {ratio:.2} at {size}");
            assert!(box_width > 80, "wider than an ordinary dialog at {size}");
        }
        for expected in [
            "Secret request from nix-secrets (pid 42)",
            "Approve to decrypt these once with 1Password.",
            "Identifier",
            "host.services.nmbl.generation-key",
            "operator key",
            "host.services.storage-box.password",
            "primary SHA256:abcdefgh",
            "1Password",
            "nix-secrets with-secrets",
            "/home/op/config",
            "via nmbl-install (41)",
            "denies in 8",
            "Ctrl+Shift+Y Yes, send",
            "n Deny",
            "Esc Deny",
            "d Details",
        ] {
            assert!(screen.contains(expected), "missing {expected:?} at {size}");
        }
        // Full fingerprints and argv wait behind Details; no prose paragraph.
        for hidden in [FINGERPRINT, "--generation-key-command", "hands them only"] {
            assert!(!screen.contains(hidden), "{hidden:?} shown at {size}");
        }
        // Each summary line fits on one row: nothing wraps.
        let cwd_rows = screen.lines().filter(|row| row.contains("Cwd")).count();
        assert_eq!(cwd_rows, 1, "{size}");
    }
    // With room, the description is shown; on a narrow screen it is not.
    assert!(render(&model, 200, 60).contains("every boot generation of dns-vps"));
    assert!(!render(&model, 60, 20).contains("NMBL generation"));
}

#[test]
fn d_shows_the_details_and_hides_them_again() {
    let mut model = model(true);
    let mut writer = Requests::default();
    writer.prompts.push(detailed_prompt());
    crate::ui::secret_request_tick_for_tests(&mut model, &mut writer);
    reduce(&mut model, UiEvent::Character('d'), &mut writer);
    assert!(model.secret_prompt.is_some(), "d never answers");
    assert!(writer.answers.is_empty());
    for (width, height) in [(200, 60), (120, 40), (80, 24), (60, 20)] {
        let screen = render(&model, width, height);
        modal_box(&screen);
        assert!(screen.contains("d Summary"), "{screen}");
        assert!(screen.contains("Requester: PID 42"), "{screen}");
        assert!(screen.contains("denies in"), "{screen}");
        if height >= 40 {
            // Nothing is cut off where the screen has room; it wraps.
            let flat: String = screen.split(['│', '\n']).map(str::trim).collect();
            for expected in [
                FINGERPRINT,
                "every boot generation of dns-vps",
                "--generation-key-command",
                "Parent: PID 41, /bin/nmbl-install",
                "1Password on this machine",
            ] {
                assert!(flat.contains(expected), "missing {expected:?} in\n{screen}");
            }
        }
    }
    // The button toggles as well.
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Shortcut(Shortcut::Character('d'))),
        &mut writer,
    );
    let screen = render(&model, 120, 40);
    assert!(screen.contains("d Details") && !screen.contains(FINGERPRINT));
    // A new request starts with the summary.
    reduce(&mut model, UiEvent::Character('d'), &mut writer);
    reduce(&mut model, UiEvent::Escape, &mut writer);
    assert_eq!(writer.answers, [("r".to_owned(), false)]);
    writer.prompts.push(detailed_prompt());
    crate::ui::secret_request_tick_for_tests(&mut model, &mut writer);
    assert!(!model.secret_details);
}
