use super::*;
use crate::model::{ApprovalRequest, HostMutationReview, Mode, Model};
use crate::operator_channel::SecretPrompt;
use crate::secret_values::RequestedValue;
use nix_secrets_core::procedure::ProcedureStep;
use nix_secrets_core::secret_request::ProcessInfo;
use std::collections::HashMap;

fn profile(terminal: Terminal, desktop: bool) -> Profile {
    Profile {
        terminal,
        sequence: terminal.sequence(),
        tmux: false,
        desktop,
        desktop_entry: terminal.desktop_entry(),
    }
}

fn console() -> Profile {
    profile(Terminal::Console, true)
}

fn prompt(id: &str, deadline: Option<Instant>, step: Option<(u32, &str)>) -> SecretPrompt {
    SecretPrompt {
        id: id.into(),
        ssh_signature: false,
        ssh_login: false,
        artifact_signature: false,
        closure_signature: step.is_some(),
        reason: None,
        values: vec![RequestedValue {
            identifier: "host.services.a.key".into(),
            kind: "secret".into(),
            description: None,
            recipients: vec![],
        }],
        identity: "1Password on this machine".into(),
        requester: ProcessInfo {
            pid: 42,
            executable: Some("/bin/nix-secrets".into()),
            argv: vec!["x".into()],
            cwd: None,
        },
        parent: None,
        deadline,
        procedure: step.map(|(number, label)| ProcedureStep {
            id: "proc-1".into(),
            title: "Update ns1".into(),
            step: number,
            steps: Some(3),
            label: label.into(),
            deployment: false,
            failure: None,
            warning: None,
            progress: None,
        }),
        confirmation: None,
    }
}

const ANNOUNCE_TITLE: &str = "\x1b[22;2t\x1b]2;(!) nix-secrets: approval needed\x07";
const RESTORE: &str = "\x1b]2;nix-secrets\x07\x1b[23;2t";

fn notify(key: &str, summary: &str, body: &str) -> DesktopCall {
    DesktopCall::Notify {
        key: key.into(),
        summary: summary.into(),
        body: body.into(),
    }
}

fn close(key: &str) -> DesktopCall {
    DesktopCall::Close { key: key.into() }
}

#[test]
fn gnome_console_gets_the_bell_the_title_and_one_bus_notification_per_event() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    assert!(attention.update(Some(&model), &console(), now).is_empty());
    model.offer_prompt(prompt("r1", Some(now + Duration::from_secs(120)), None));
    assert_eq!(
        attention.update(Some(&model), &console(), now),
        Signals {
            // No escape sequence: VTE shows none of them.
            terminal: format!("\x07{ANNOUNCE_TITLE}"),
            desktop: vec![notify(
                "secret:r1",
                "nix-secrets: approval needed",
                "Secret request from nix-secrets (pid 42) · denies in 120 s"
            )],
        }
    );
    // Every frame after that: nothing, until the reminder.
    for seconds in [1, 50, 89] {
        let later = now + Duration::from_secs(seconds);
        assert!(attention.update(Some(&model), &console(), later).is_empty(), "{seconds}");
    }
    let reminder = now + Duration::from_secs(90);
    assert_eq!(
        attention.update(Some(&model), &console(), reminder),
        Signals {
            terminal: "\x07".into(),
            desktop: vec![notify(
                "secret:r1",
                "nix-secrets: 30 s left to answer",
                "Secret request from nix-secrets (pid 42)"
            )],
        }
    );
    let after = now + Duration::from_secs(110);
    assert!(attention.update(Some(&model), &console(), after).is_empty(), "one reminder");
    // Answered: the title goes back and the notification closes.
    model.remove_prompt("r1");
    assert_eq!(
        attention.update(Some(&model), &console(), after),
        Signals {
            terminal: RESTORE.into(),
            desktop: vec![close("secret:r1")],
        }
    );
    assert!(attention.update(Some(&model), &console(), after).is_empty());
}

#[test]
fn each_terminal_gets_exactly_one_notification_sequence() {
    let now = Instant::now();
    let summary = "nix-secrets: approval needed";
    let body = "Update ns1 · step 1/3: sign closure for ns1 · denies in 120 s";
    let cases = [
        (
            Terminal::Kitty,
            format!(
                "\x1b]99;i=nix-secrets-1:d=0:u=2;{summary}\x1b\\\x1b]99;i=nix-secrets-1:p=body;{body}\x1b\\"
            ),
        ),
        (Terminal::Foot, format!("\x1b]777;notify;{summary};{body}\x07")),
        (Terminal::WezTerm, format!("\x1b]777;notify;{summary};{body}\x07")),
        (Terminal::Ghostty, format!("\x1b]777;notify;{summary};{body}\x07")),
        (Terminal::Konsole, format!("\x1b]777;notify;{summary};{body}\x07")),
        (
            Terminal::ITerm2,
            format!("\x1b]9;{summary}: {body}\x07\x1b]1337;RequestAttention=yes\x07"),
        ),
        (Terminal::WindowsTerminal, String::new()),
        (Terminal::Alacritty, String::new()),
        (Terminal::GnomeTerminal, String::new()),
    ];
    for (terminal, sequence) in cases {
        let mut attention = Attention::default();
        let mut model = Model::new(vec![]);
        model.offer_prompt(prompt(
            "r1",
            Some(now + Duration::from_secs(120)),
            Some((1, "sign closure for ns1")),
        ));
        let signals = attention.update(Some(&model), &profile(terminal, false), now);
        assert_eq!(
            signals.terminal,
            format!("\x07{sequence}{ANNOUNCE_TITLE}"),
            "{terminal:?}"
        );
        assert!(signals.desktop.is_empty(), "{terminal:?}");
    }
}

#[test]
fn tmux_wraps_the_sequence_in_its_passthrough() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    model.offer_prompt(prompt("r1", None, None));
    let mut foot = profile(Terminal::Foot, false);
    foot.tmux = true;
    assert_eq!(
        attention.update(Some(&model), &foot, now).terminal,
        format!(
            "\x07\x1bPtmux;\x1b\x1b]777;notify;nix-secrets: approval needed;Secret request from nix-secrets (pid 42)\x07\x1b\\{ANNOUNCE_TITLE}"
        )
    );
}

#[test]
fn names_cannot_inject_sequences_and_semicolons_cannot_split_osc_777() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    let mut evil = prompt("r1", None, None);
    evil.requester.executable = Some("/bin/a\x1b]2;owned\x07;b".into());
    model.offer_prompt(evil);
    let signals = attention.update(Some(&model), &profile(Terminal::Foot, false), now);
    assert_eq!(
        signals.terminal,
        format!(
            "\x07\x1b]777;notify;nix-secrets: approval needed;Secret request from a]2,owned,b (pid 42)\x07{ANNOUNCE_TITLE}"
        )
    );
    let mut attention = Attention::default();
    let signals = attention.update(Some(&model), &console(), now);
    assert_eq!(
        signals.desktop,
        [notify(
            "secret:r1",
            "nix-secrets: approval needed",
            "Secret request from a]2;owned;b (pid 42)"
        )]
    );
}

#[test]
fn a_countdown_that_starts_later_notifies_again_and_cancelling_it_does_not() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    // A later step of a procedure waits without a countdown.
    model.offer_prompt(prompt("r1", None, Some((2, "sign closure for ns1"))));
    let first = attention.update(Some(&model), &console(), now);
    assert_eq!(
        first.desktop,
        [notify(
            "secret:r1",
            "nix-secrets: approval needed",
            "Update ns1 · step 2/3: sign closure for ns1"
        )]
    );
    assert!(attention.update(Some(&model), &console(), now).is_empty());
    // Sent again after reconnecting, it counts down.
    model.procedures[0].prompts[0].deadline = Some(now + Duration::from_secs(120));
    assert_eq!(
        attention.update(Some(&model), &console(), now),
        Signals {
            terminal: "\x07".into(),
            desktop: vec![notify(
                "secret:r1",
                "nix-secrets: countdown started",
                "Update ns1 · step 2/3: sign closure for ns1 · denies in 120 s"
            )],
        }
    );
    assert!(attention.update(Some(&model), &console(), now).is_empty(), "once");
    // The operator cancels it: nothing to tell.
    model.procedures[0].prompts[0].deadline = None;
    let later = now + Duration::from_secs(100);
    assert!(attention.update(Some(&model), &console(), later).is_empty());
}

#[test]
fn a_request_that_arrives_late_gets_no_reminder_at_once() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    model.offer_prompt(prompt("r1", Some(now + Duration::from_secs(20)), None));
    let signals = attention.update(Some(&model), &console(), now);
    assert_eq!(signals.desktop.len(), 1);
    assert!(attention
        .update(Some(&model), &console(), now + Duration::from_secs(5))
        .is_empty());
}

#[test]
fn a_procedure_in_the_task_bar_notifies_once_and_restoring_it_only_sets_the_title() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    model.offer_prompt(prompt("first", None, None));
    attention.update(Some(&model), &console(), now);
    // A second request arrives while the first is open: it flashes.
    model.offer_prompt(prompt("second", Some(now + Duration::from_secs(120)), Some((1, "x"))));
    assert!(model.procedure("proc-1").unwrap().flashing);
    assert_eq!(
        attention.update(Some(&model), &console(), now),
        Signals {
            terminal: "\x07".into(),
            desktop: vec![notify(
                "secret:second",
                "nix-secrets: approval needed",
                "Update ns1 · step 1/3: x waits in the task bar · denies in 120 s"
            )],
        }
    );
    // Its reminder comes while it waits there.
    let reminder = now + Duration::from_secs(95);
    let signals = attention.update(Some(&model), &console(), reminder);
    assert_eq!(signals.terminal, "\x07");
    assert_eq!(signals.desktop.len(), 1);
    // The first is answered, the second restored: title only.
    model.remove_prompt("first");
    model.restore("proc-1").unwrap();
    assert_eq!(
        attention.update(Some(&model), &console(), reminder),
        Signals {
            terminal: format!("{RESTORE}{ANNOUNCE_TITLE}"),
            desktop: vec![close("secret:first")],
        }
    );
}

#[test]
fn a_timed_out_step_notifies_once_until_acknowledged_and_a_denial_not_at_all() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    model.offer_prompt(prompt("r1", Some(now), Some((1, "sign closure for ns1"))));
    attention.update(Some(&model), &console(), now);
    assert!(model.expire_prompts(now));
    assert_eq!(
        attention.update(Some(&model), &console(), now),
        Signals {
            terminal: format!("{RESTORE}\x07"),
            desktop: vec![
                close("secret:r1"),
                notify(
                    "missed:proc-1",
                    "nix-secrets: step timed out",
                    "Update ns1 timed out at step 1/3: sign closure for ns1"
                ),
            ],
        }
    );
    assert!(attention.update(Some(&model), &console(), now).is_empty());
    model.dismiss_result();
    assert_eq!(
        attention.update(Some(&model), &console(), now),
        Signals {
            terminal: String::new(),
            desktop: vec![close("missed:proc-1")],
        }
    );
    // The operator's own denial is no news.
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    model.offer_prompt(prompt("r2", None, Some((1, "x"))));
    attention.update(Some(&model), &console(), now);
    model.take_shown_prompt(false);
    model.step_finished("r2", Err("the operator denied it".into()));
    assert!(model.procedure("proc-1").unwrap().failed());
    let signals = attention.update(Some(&model), &console(), now);
    assert_eq!(signals.terminal, RESTORE);
    assert_eq!(signals.desktop, [close("secret:r2")]);
}

#[test]
fn closing_the_tui_restores_the_title_and_closes_its_notifications() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    model.offer_prompt(prompt("r1", None, None));
    attention.update(Some(&model), &console(), now);
    assert_eq!(
        attention.update(None, &console(), now),
        Signals {
            terminal: RESTORE.into(),
            desktop: vec![close("secret:r1")],
        }
    );
}

#[test]
fn deployment_approval_announces_once_and_restores_the_title() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    let foot = profile(Terminal::Foot, false);
    model.mode = Mode::Approval(ApprovalRequest {
        id: "1".into(),
        target: "untrusted\x1bhost".into(),
        ..Default::default()
    });
    let text = attention.update(Some(&model), &foot, now).terminal;
    assert_eq!(
        text,
        "\x07\x1b]777;notify;nix-secrets: approval needed;Deployment approval requested\x07\
         \x1b[22;2t\x1b]2;(!) nix-secrets: deployment approval needed\x07"
    );
    assert!(!text.contains("untrusted"));
    assert!(attention.update(Some(&model), &foot, now).is_empty());
    model.mode = Mode::Browse;
    assert_eq!(attention.update(Some(&model), &foot, now).terminal, RESTORE);
}

#[test]
fn the_host_change_phase_of_the_same_request_gets_its_own_announcement() {
    let now = Instant::now();
    let mut attention = Attention::default();
    let mut model = Model::new(vec![]);
    let foot = profile(Terminal::Foot, false);
    let normal = ApprovalRequest {
        id: "same".into(),
        target: "producer".into(),
        ..Default::default()
    };
    model.mode = Mode::Approval(normal.clone());
    assert!(!attention.update(Some(&model), &foot, now).is_empty());
    let mut review = normal;
    review.host_mutation_token = Some("exact-review".into());
    review.host_mutations.push(HostMutationReview {
        identifier: "receiver.known-hosts".into(),
        kind: "receiver host identity".into(),
        previous: vec!["SHA256:old".into()],
        proposed: vec!["SHA256:new".into()],
    });
    model.mode = Mode::Approval(review);
    let text = attention.update(Some(&model), &foot, now).terminal;
    // The previous title goes before the new bell.
    assert!(text.starts_with(&format!("{RESTORE}\x07")), "{text:?}");
    assert!(text.contains("Save host-provided changes requested"));
    assert!(text.contains("2;(!) nix-secrets: save host-provided changes"));
    assert!(!text.contains("exact-review"), "no internal token in a notification");
    assert!(attention.update(Some(&model), &foot, now).is_empty());
}

fn detect(pairs: &[(&str, &str)], local_bus: bool, passthrough: bool) -> Profile {
    let map: HashMap<&str, &str> = pairs.iter().copied().collect();
    Profile::detect(
        &|name| map.get(name).map(|value| (*value).to_owned()),
        local_bus,
        || passthrough,
    )
}

#[test]
fn the_terminal_is_detected_from_its_environment() {
    let cases: &[(&[(&str, &str)], Terminal)] = &[
        (&[("TERM_PROGRAM", "kgx"), ("VTE_VERSION", "8401")], Terminal::Console),
        (&[("VTE_VERSION", "8401"), ("TERM", "xterm-256color")], Terminal::GnomeTerminal),
        (&[("TERM", "xterm-kitty")], Terminal::Kitty),
        (&[("KITTY_WINDOW_ID", "1"), ("TERM", "tmux-256color")], Terminal::Kitty),
        (&[("TERM", "foot")], Terminal::Foot),
        (&[("TERM", "foot-extra")], Terminal::Foot),
        (&[("TERM_PROGRAM", "WezTerm")], Terminal::WezTerm),
        (&[("TERM_PROGRAM", "ghostty")], Terminal::Ghostty),
        (&[("TERM_PROGRAM", "iTerm.app")], Terminal::ITerm2),
        (&[("KONSOLE_VERSION", "251100")], Terminal::Konsole),
        (&[("WT_SESSION", "abc")], Terminal::WindowsTerminal),
        (&[("TERM", "alacritty")], Terminal::Alacritty),
        (&[("TERM", "xterm-256color")], Terminal::Unknown),
        // The innermost terminal wins over variables inherited from an outer one.
        (&[("TERM_PROGRAM", "WezTerm"), ("KITTY_WINDOW_ID", "3")], Terminal::WezTerm),
    ];
    for (environment, terminal) in cases {
        assert_eq!(detect(environment, false, false).terminal, *terminal, "{environment:?}");
    }
}

#[test]
fn the_session_bus_is_used_where_no_sequence_works_and_can_be_turned_off() {
    let console = [("TERM_PROGRAM", "kgx"), ("VTE_VERSION", "8401")];
    let local = detect(&console, true, false);
    assert_eq!((local.sequence, local.desktop), (Sequence::None, true));
    assert_eq!(local.desktop_entry, Some("org.gnome.Console"));
    // Over SSH there is no local bus: the bell and the title remain.
    let remote = detect(&console, false, false);
    assert_eq!((remote.sequence, remote.desktop), (Sequence::None, false));
    let off = detect(&[console[0], (DESKTOP_SETTING, "off")], true, false);
    assert!(!off.desktop);
    // A terminal with its own notifications does not get a second one.
    let kitty = detect(&[("TERM", "xterm-kitty")], true, false);
    assert_eq!((kitty.sequence, kitty.desktop), (Sequence::Osc99, false));
    let always = detect(&[("TERM", "xterm-kitty"), (DESKTOP_SETTING, "always")], true, false);
    assert_eq!((always.sequence, always.desktop), (Sequence::Osc99, true));
    // An unknown terminal: the bus where local, else OSC 777 on the chance.
    let unknown = detect(&[("TERM", "xterm-256color")], true, false);
    assert_eq!((unknown.sequence, unknown.desktop), (Sequence::None, true));
    let unknown = detect(&[("TERM", "xterm-256color")], false, false);
    assert_eq!((unknown.sequence, unknown.desktop), (Sequence::Osc777, false));
}

#[test]
fn tmux_without_passthrough_falls_back_to_the_session_bus() {
    let kitty_in_tmux = [
        ("TERM", "tmux-256color"),
        ("TERM_PROGRAM", "tmux"),
        ("KITTY_WINDOW_ID", "1"),
        ("TMUX", "/tmp/tmux-1000/default,1,0"),
    ];
    let passing = detect(&kitty_in_tmux, true, true);
    assert_eq!(
        (passing.terminal, passing.sequence, passing.tmux, passing.desktop),
        (Terminal::Kitty, Sequence::Osc99, true, false)
    );
    let blocked = detect(&kitty_in_tmux, true, false);
    assert_eq!(
        (blocked.sequence, blocked.tmux, blocked.desktop),
        (Sequence::None, true, true)
    );
}
