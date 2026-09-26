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
}

impl Attention {
    /// The bytes to write after the next frame for the request now open,
    /// if any: an announcement for a new one, a bell at [`REMINDER_AT`],
    /// and the old title once it closed.
    pub(super) fn update(
        &mut self,
        prompt: Option<&SecretPrompt>,
        remaining: Duration,
        tmux: bool,
    ) -> Option<Vec<u8>> {
        let mut output = String::new();
        let current = prompt.map(|prompt| prompt.id.as_str());
        if self.announced.is_some() && self.announced.as_deref() != current {
            self.announced = None;
            output.push_str(&restore());
        }
        if let Some(prompt) = prompt {
            if self.announced.is_none() {
                self.announced = Some(prompt.id.clone());
                // A request that arrives late never rings twice at once.
                self.reminded = remaining <= REMINDER_AT;
                output.push_str(&announce(&super::secret_request::title(prompt), tmux));
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
pub(super) fn announce(summary: &str, tmux: bool) -> String {
    // The summary names a program read from /proc: no control character in
    // it may end the sequence early or start another one.
    let summary: String = summary.chars().filter(|c| !c.is_control()).collect();
    format!(
        "{BEL}{}{}{PUSH_TITLE}\x1b]2;{REQUEST_TITLE}\x07",
        passthrough(&format!("\x1b]777;notify;nix-secrets;{summary}\x07"), tmux),
        passthrough(&format!("\x1b]9;nix-secrets: {summary}\x07"), tmux),
    )
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
            deadline: Instant::now(),
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
