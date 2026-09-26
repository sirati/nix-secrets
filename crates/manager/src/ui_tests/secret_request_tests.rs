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

#[test]
fn the_modal_lists_values_keys_and_the_requesting_program() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut model = model(true);
    model.secret_prompt = Some(prompt("r", Instant::now() + Duration::from_secs(90)));
    let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
    let screen = crate::ui::render_for_tests(&mut terminal, &model);
    for expected in [
        "Secret request",
        "host.services.nmbl.generation-key (operator key)",
        "NMBL generation signing key",
        "recipient primary: ssh-ed25519 SHA256:abc",
        "Program: PID 41, /bin/nmbl-install",
        "command: nmbl-install --target dns-vps",
        "cwd: /home/op/config",
        "Requester: PID 42",
        "1Password on this machine",
        "Denies automatically in 8",
        "Ctrl+Shift+Y Yes, send",
    ] {
        assert!(
            screen.contains(expected),
            "missing {expected:?} in\n{screen}"
        );
    }
}
