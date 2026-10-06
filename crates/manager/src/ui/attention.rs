//! Gets the operator's attention when a secret request opens, since the TUI
//! may sit in a background window or tab.
//!
//! Once per request the terminal receives, after a frame is drawn and never
//! inside one:
//!
//! - BEL. GNOME Console and other VTE terminals turn it into an urgency
//!   hint on the window by default; kitty, WezTerm and Konsole flash or mark
//!   the tab depending on their bell settings (kitty `enable_audio_bell`,
//!   `window_alert_on_bell`; WezTerm `audible_bell`/`visual_bell`). tmux
//!   passes it on when `bell-action` covers the pane (`any` by default) and
//!   the outer terminal then reacts as above.
//! - OSC 777 `notify`, a desktop notification in VTE terminals such as
//!   GNOME Console and GNOME Terminal (Fedora/Ubuntu builds), and OSC 9, a
//!   notification in iTerm2, kitty, WezTerm, Windows Terminal and foot.
//!   Inside tmux (`$TMUX` set) both are wrapped in tmux's DCS passthrough,
//!   which needs `set -g allow-passthrough on` (tmux 3.3 or later).
//! - The window title "⚠ nix-secrets: secret request" (OSC 2), after
//!   pushing the current title on the terminal's title stack (CSI 22;2 t).
//!   When the request closes, the title is set to "nix-secrets" and then
//!   popped (CSI 23;2 t); a terminal without a title stack keeps
//!   "nix-secrets" instead of the warning.
//!
//! When 30 seconds are left, BEL sounds once more. Terminals that support
//! none of this ignore the sequences.
//!
//! A procedure that starts or asks again while another dialog is open stays
//! in the task bar and flashes there. Its request gets the bell and the
//! desktop notifications once, without the window title, which belongs to
//! the dialog on screen; restoring it later only sets the title.
use crate::operator_channel::SecretPrompt;
use std::time::Duration;

/// When the second bell sounds.
pub(super) const REMINDER_AT: Duration = Duration::from_secs(30);

/// The window title while a request is open.
pub(super) const REQUEST_TITLE: &str = "⚠ nix-secrets: secret request";
/// The title left behind by a terminal without a title stack.
pub(super) const IDLE_TITLE: &str = "nix-secrets";

const BEL: &str = "\x07";
const PUSH_TITLE: &str = "\x1b[22;2t";
const POP_TITLE: &str = "\x1b[23;2t";

/// What has been signalled for the open request.
#[derive(Debug, Default)]
pub(super) struct Attention {
    /// The request that was announced, while it is open.
    announced: Option<String>,
    reminded: bool,
    /// Requests announced while their procedure flashed in the task bar.
    background: std::collections::BTreeSet<String>,
    /// Of those, the ones whose countdown reminder rang.
    background_reminded: std::collections::BTreeSet<String>,
}

/// The request a procedure waits on, as the attention key of its dialog.
fn waiting_request(model: &crate::model::Model, procedure: &crate::model::Procedure) -> Option<String> {
    if let Some(prompt) = procedure.prompts.front() {
        return Some(format!("secret:{}", prompt.id));
    }
    if let crate::model::Mode::Approval(request) = &model.mode {
        if crate::model::approval_procedure(request) == procedure.id {
            return Some(format!("deployment:{}", request.id));
        }
    }
    model
        .pending_approvals
        .iter()
        .find(|request| crate::model::approval_procedure(request) == procedure.id)
        .map(|request| format!("deployment:{}", request.id))
}

impl Attention {
    pub(super) fn update_model(
        &mut self,
        model: Option<&crate::model::Model>,
        tmux: bool,
    ) -> Option<Vec<u8>> {
        let background = model.map(|model| self.background(model, tmux));
        let foreground = self.foreground(model, tmux);
        match (foreground, background.flatten()) {
            (None, None) => None,
            (Some(bytes), None) | (None, Some(bytes)) => Some(bytes),
            (Some(mut first), Some(second)) => {
                first.extend(second);
                Some(first)
            }
        }
    }

    /// Bell and notifications for procedures that flash in the task bar.
    fn background(&mut self, model: &crate::model::Model, tmux: bool) -> Option<Vec<u8>> {
        let mut output = String::new();
        let mut current = std::collections::BTreeSet::new();
        for procedure in model.procedures.iter().filter(|procedure| procedure.flashing) {
            let Some(key) = waiting_request(model, procedure) else {
                continue;
            };
            current.insert(key.clone());
            if self.background.insert(key.clone()) {
                output.push_str(&announce_quietly(
                    &format!("{} waits in the task bar", procedure.heading()),
                    tmux,
                ));
            }
            let remaining = procedure
                .prompts
                .front()
                .and_then(|prompt| prompt.deadline)
                .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()));
            if remaining.is_some_and(|left| left <= REMINDER_AT)
                && self.background_reminded.insert(key)
            {
                output.push_str(BEL);
            }
        }
        // Restored requests stay known, so their dialog does not ring again.
        let open = model
            .procedures
            .iter()
            .filter_map(|procedure| waiting_request(model, procedure))
            .collect::<std::collections::BTreeSet<_>>();
        self.background.retain(|key| open.contains(key));
        self.background_reminded.retain(|key| current.contains(key));
        (!output.is_empty()).then(|| output.into_bytes())
    }

    fn foreground(
        &mut self,
        model: Option<&crate::model::Model>,
        tmux: bool,
    ) -> Option<Vec<u8>> {
        let prompt = model.and_then(|model| model.shown_prompt());
        let remaining = prompt
            .and_then(|prompt| prompt.deadline)
            .map_or(Duration::MAX, |deadline| {
                deadline.saturating_duration_since(std::time::Instant::now())
            });
        if prompt.is_some() {
            self.update(prompt, remaining, tmux)
        } else if let Some(crate::model::Model {
            mode: crate::model::Mode::Approval(request),
            ..
        }) = model
        {
            let replacement = !request.host_mutations.is_empty();
            let id = if replacement {
                format!(
                    "host-mutations:{}:{}",
                    request.id,
                    request.host_mutation_token.as_deref().unwrap_or("missing")
                )
            } else {
                format!("deployment:{}", request.id)
            };
            self.update_request(
                Some((
                    &id,
                    if replacement {
                        "Save host-provided changes requested"
                    } else {
                        "Deployment approval requested"
                    },
                    if replacement {
                        "⚠ nix-secrets: save host-provided changes"
                    } else {
                        "⚠ nix-secrets: deployment approval"
                    },
                )),
                remaining,
                tmux,
            )
        } else {
            self.update(None, remaining, tmux)
        }
    }

    /// The bytes to write after the next frame for the request now open,
    /// if any: an announcement for a new one, a bell at [`REMINDER_AT`],
    /// and the old title once it closed.
    pub(super) fn update(
        &mut self,
        prompt: Option<&SecretPrompt>,
        remaining: Duration,
        tmux: bool,
    ) -> Option<Vec<u8>> {
        let request = prompt.map(|prompt| {
            (
                format!("secret:{}", prompt.id),
                super::secret_request::title(prompt),
                REQUEST_TITLE,
            )
        });
        self.update_request(
            request
                .as_ref()
                .map(|(id, summary, title)| (id.as_str(), summary.as_str(), *title)),
            remaining,
            tmux,
        )
    }

    pub(super) fn update_request(
        &mut self,
        request: Option<(&str, &str, &str)>,
        remaining: Duration,
        tmux: bool,
    ) -> Option<Vec<u8>> {
        let mut output = String::new();
        let current = request.map(|(id, _, _)| id);
        if self.announced.is_some() && self.announced.as_deref() != current {
            self.announced = None;
            output.push_str(&restore());
        }
        if let Some((id, summary, title)) = request {
            if self.announced.is_none() {
                self.announced = Some(id.to_owned());
                self.reminded = remaining <= REMINDER_AT;
                if self.background.contains(id) {
                    // Already rung for while it flashed in the task bar.
                    output.push_str(&title_only(title));
                } else {
                    output.push_str(&announce_with_title(summary, title, tmux));
                }
            } else if !self.reminded && remaining <= REMINDER_AT {
                self.reminded = true;
                output.push_str(BEL);
            }
        }
        (!output.is_empty()).then(|| output.into_bytes())
    }
}

/// Whether the TUI runs inside tmux.
pub(super) fn in_tmux() -> bool {
    std::env::var_os("TMUX").is_some_and(|value| !value.is_empty())
}

/// The bell, the notifications and the warning title for `summary`.
#[cfg(test)]
pub(super) fn announce(summary: &str, tmux: bool) -> String {
    announce_with_title(summary, REQUEST_TITLE, tmux)
}

fn announce_with_title(summary: &str, title: &str, tmux: bool) -> String {
    // The summary names a program read from /proc: no control character in
    // it may end the sequence early or start another one.
    let summary: String = summary.chars().filter(|c| !c.is_control()).collect();
    let title: String = title.chars().filter(|c| !c.is_control()).collect();
    format!(
        "{BEL}{}{}{PUSH_TITLE}\x1b]2;{title}\x07",
        passthrough(&format!("\x1b]777;notify;nix-secrets;{summary}\x07"), tmux),
        passthrough(&format!("\x1b]9;nix-secrets: {summary}\x07"), tmux),
    )
}

/// The bell and the notifications, without touching the window title.
fn announce_quietly(summary: &str, tmux: bool) -> String {
    let summary: String = summary.chars().filter(|c| !c.is_control()).collect();
    format!(
        "{BEL}{}{}",
        passthrough(&format!("\x1b]777;notify;nix-secrets;{summary}\x07"), tmux),
        passthrough(&format!("\x1b]9;nix-secrets: {summary}\x07"), tmux),
    )
}

/// The warning title alone.
fn title_only(title: &str) -> String {
    let title: String = title.chars().filter(|c| !c.is_control()).collect();
    format!("{PUSH_TITLE}\x1b]2;{title}\x07")
}

/// Takes the warning title away again.
pub(super) fn restore() -> String {
    format!("\x1b]2;{IDLE_TITLE}\x07{POP_TITLE}")
}

/// Wraps a sequence so tmux hands it to the outer terminal.
fn passthrough(sequence: &str, tmux: bool) -> String {
    if tmux {
        format!("\x1bPtmux;{}\x1b\\", sequence.replace('\x1b', "\x1b\x1b"))
    } else {
        sequence.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_values::RequestedValue;
    use nix_secrets_core::secret_request::ProcessInfo;
    use std::time::Instant;

    fn prompt(id: &str, executable: &str) -> SecretPrompt {
        SecretPrompt {
            id: id.into(),
            ssh_signature: false,
            artifact_signature: false,
            closure_signature: false,
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
                executable: Some(executable.into()),
                argv: vec!["x".into()],
                cwd: None,
            },
            parent: None,
            deadline: Some(Instant::now()),
            procedure: None,
        }
    }

    const ANNOUNCE: &str = concat!(
        "\x07",
        "\x1b]777;notify;nix-secrets;Secret request from nix-secrets (pid 42)\x07",
        "\x1b]9;nix-secrets: Secret request from nix-secrets (pid 42)\x07",
        "\x1b[22;2t",
        "\x1b]2;⚠ nix-secrets: secret request\x07",
    );
    const RESTORE: &str = "\x1b]2;nix-secrets\x07\x1b[23;2t";

    #[test]
    fn a_request_is_announced_once_reminded_once_and_its_title_restored() {
        let mut attention = Attention::default();
        let request = prompt("r1", "/bin/nix-secrets");
        let long = Duration::from_secs(120);
        let at = |attention: &mut Attention, prompt, left| {
            attention
                .update(prompt, left, false)
                .map(|bytes| String::from_utf8(bytes).unwrap())
        };
        assert_eq!(at(&mut attention, None, long), None);
        assert_eq!(
            at(&mut attention, Some(&request), long).as_deref(),
            Some(ANNOUNCE)
        );
        assert_eq!(at(&mut attention, Some(&request), long), None, "only once");
        assert_eq!(
            at(&mut attention, Some(&request), Duration::from_secs(30)).as_deref(),
            Some("\x07")
        );
        assert_eq!(
            at(&mut attention, Some(&request), Duration::from_secs(10)),
            None,
            "the reminder rings once"
        );
        assert_eq!(at(&mut attention, None, long).as_deref(), Some(RESTORE));
        assert_eq!(at(&mut attention, None, long), None);
        // A request that follows directly restores and announces again.
        let next = prompt("r2", "/bin/nix-secrets");
        at(&mut attention, Some(&request), long);
        assert_eq!(
            at(&mut attention, Some(&next), Duration::from_secs(20)),
            Some(format!("{RESTORE}{ANNOUNCE}")),
            "a late request does not ring its reminder at once"
        );
        assert_eq!(
            at(&mut attention, Some(&next), Duration::from_secs(5)),
            None
        );
    }

    #[test]
    fn tmux_passes_the_notifications_through_and_names_cannot_inject() {
        let tmux = announce("Secret request from a\x1b]2;owned\x07b (pid 1)", true);
        assert_eq!(
            tmux,
            concat!(
                "\x07",
                "\x1bPtmux;\x1b\x1b]777;notify;nix-secrets;Secret request from a]2;ownedb (pid 1)\x07\x1b\\",
                "\x1bPtmux;\x1b\x1b]9;nix-secrets: Secret request from a]2;ownedb (pid 1)\x07\x1b\\",
                "\x1b[22;2t",
                "\x1b]2;⚠ nix-secrets: secret request\x07",
            )
        );
    }
}

#[cfg(test)]
mod deployment_tests {
    use super::*;

    #[test]
    fn deployment_approval_announces_once_and_restores_title() {
        let mut attention = Attention::default();
        let request = Some((
            "deployment:1",
            "Deployment approval requested",
            "⚠ nix-secrets: deployment approval",
        ));
        let bytes = attention
            .update_request(request, Duration::MAX, false)
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with(BEL));
        assert!(text.contains("777;notify;nix-secrets;Deployment approval requested"));
        assert!(text.contains("9;nix-secrets: Deployment approval requested"));
        assert!(text.contains("2;⚠ nix-secrets: deployment approval"));
        assert!(attention
            .update_request(request, Duration::MAX, false)
            .is_none());
        assert_eq!(
            attention
                .update_request(None, Duration::MAX, false)
                .unwrap(),
            restore().into_bytes()
        );
        assert!(attention
            .update_request(None, Duration::MAX, false)
            .is_none());
    }
}

#[cfg(test)]
mod model_attention_tests {
    use super::*;
    use crate::model::{ApprovalRequest, Mode, Model};
    use crate::ui::{reduce, Action, SecretWriter, UiEvent};
    use zeroize::Zeroizing;

    struct Writer;
    impl SecretWriter for Writer {
        fn write(
            &mut self,
            _: &str,
            value: Zeroizing<Vec<u8>>,
        ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
            Err(("unused".into(), value))
        }
    }

    #[test]
    fn incoming_deployment_approval_interrupts_notice_and_signals_then_restores() {
        let mut model = Model::new(vec![]);
        let mut writer = Writer;
        let mut attention = Attention::default();
        model.inform("previous success");
        reduce(
            &mut model,
            UiEvent::Approval(ApprovalRequest {
                id: "request".into(),
                target: "untrusted\x1bhost".into(),
                ..Default::default()
            }),
            &mut writer,
        );
        assert!(matches!(model.mode, Mode::Approval(_)));
        assert!(model.message.is_none());
        let bytes = attention.update_model(Some(&model), false).unwrap();
        let notification = String::from_utf8(bytes).unwrap();
        assert!(notification.starts_with(BEL));
        assert!(notification.contains("Deployment approval requested"));
        assert!(notification.contains("2;⚠ nix-secrets: deployment approval"));
        assert!(!notification.contains("untrusted"));
        assert!(attention.update_model(Some(&model), false).is_none());
        reduce(&mut model, UiEvent::Character('n'), &mut writer);
        assert_eq!(model.message_text(), Some("previous success"));
        assert_eq!(
            attention.update_model(Some(&model), false).unwrap(),
            restore().into_bytes()
        );
    }
}

#[cfg(test)]
mod host_mutation_attention_tests {
    use super::*;
    use crate::model::{ApprovalRequest, HostMutationReview, Mode, Model};
    #[test]
    fn same_request_replacement_phase_gets_its_own_bell_title_and_notification() {
        let mut model = Model::new(vec![]);
        let mut attention = Attention::default();
        let normal = ApprovalRequest {
            id: "same".into(),
            target: "producer".into(),
            ..Default::default()
        };
        model.mode = Mode::Approval(normal.clone());
        assert!(attention.update_model(Some(&model), false).is_some());
        let mut review = normal;
        review.host_mutation_token = Some("exact-review".into());
        review.host_mutations.push(HostMutationReview {
            identifier: "receiver.known-hosts".into(),
            kind: "receiver host identity".into(),
            previous: vec!["SHA256:old".into()],
            proposed: vec!["SHA256:new".into()],
        });
        model.mode = Mode::Approval(review);
        let bytes = attention
            .update_model(Some(&model), false)
            .expect("post-deploy phase needs fresh attention");
        let notification = String::from_utf8(bytes).unwrap();
        // Changing phases restores the previous request title before the new bell.
        assert!(notification.starts_with(&format!("{}{BEL}", restore())));
        assert!(notification.contains("Save host-provided changes requested"));
        assert!(notification.contains("2;⚠ nix-secrets: save host-provided changes"));
        assert!(
            !notification.contains("exact-review"),
            "internal token must not enter desktop notification"
        );
        assert!(attention.update_model(Some(&model), false).is_none());
    }
}
