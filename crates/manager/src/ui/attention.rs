//! Gets the operator's attention when a request needs an answer, since the
//! TUI may sit in a background window or tab, and when a procedure step was
//! missed.
//!
//! Each event rings BEL and raises one desktop notification. What carries
//! the notification depends on the terminal ([`Profile::detect`]), because
//! terminals that understand several sequences show one notification for
//! each, and the VTE terminals understand none:
//!
//! | terminal | notification | BEL |
//! |---|---|---|
//! | GNOME Console, GNOME Terminal (VTE 0.84) | session bus | sound; Console marks the tab |
//! | kitty | OSC 99 | urgency hint |
//! | foot, WezTerm, Ghostty, Konsole | OSC 777 `notify` | per bell settings |
//! | iTerm2 | OSC 9, plus OSC 1337 `RequestAttention` | dock |
//! | Windows Terminal, Alacritty | session bus where local | taskbar flash, urgency |
//! | unknown | session bus where local, else OSC 777 | |
//!
//! Upstream VTE has no notification sequence: OSC 777 is honoured only
//! behind the off-by-default `enable-legacy-osc777`, and then only for
//! "Command completed"; OSC 9 is `9;4` progress only. GNOME Console sets no
//! urgency hint on BEL either. So for VTE, and wherever no sequence is
//! known to work, the TUI calls `org.freedesktop.Notifications` itself
//! ([`super::desktop_notify`]), but only in a local graphical session.
//! `NIX_SECRETS_DESKTOP_NOTIFICATIONS=off` turns that off, `=always` uses
//! it next to the terminal's sequence.
//!
//! Inside tmux the sequence is wrapped in tmux's DCS passthrough when
//! `allow-passthrough` is on; tmux itself drops OSC 99 and 777. Without
//! passthrough the session bus carries the notification. tmux forwards BEL
//! under its default `bell-action any`.
//!
//! Events, each once:
//! - a request opens: on screen, or flashing in the task bar;
//! - its countdown starts or starts again, such as a request sent again
//!   after reconnecting;
//! - [`REMINDER_AT`] before its countdown denies it;
//! - a procedure step times out or fails (a denial is the operator's own).
//!
//! While a request is on screen the window title is "(!) nix-secrets:
//! approval needed" (OSC 2), after pushing the current title on the title
//! stack (CSI 22;2 t). When it closes, the title is set to "nix-secrets" and
//! popped (CSI 23;2 t); a terminal without a title stack keeps
//! "nix-secrets". Its desktop notification is closed then too.
//!
//! All bytes go out after a frame is drawn, never inside one.
use super::desktop_notify::DesktopCall;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// When the reminder comes.
pub(super) const REMINDER_AT: Duration = Duration::from_secs(30);

/// The window title while a request is open.
pub(super) const REQUEST_TITLE: &str = "(!) nix-secrets: approval needed";
/// The title left behind by a terminal without a title stack.
pub(super) const IDLE_TITLE: &str = "nix-secrets";

const BEL: &str = "\x07";
const PUSH_TITLE: &str = "\x1b[22;2t";
const POP_TITLE: &str = "\x1b[23;2t";
/// Longest summary or body sent to the terminal or the desktop.
const MAX_TEXT: usize = 240;

/// The terminal the TUI runs in, as far as its environment tells.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Terminal {
    Console,
    GnomeTerminal,
    Kitty,
    Foot,
    WezTerm,
    Ghostty,
    Konsole,
    ITerm2,
    WindowsTerminal,
    Alacritty,
    Unknown,
}

/// The escape sequence that raises a desktop notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Sequence {
    None,
    /// `OSC 777 ; notify ; TITLE ; BODY`
    Osc777,
    /// `OSC 9 ; TEXT`
    Osc9,
    /// kitty's `OSC 99`
    Osc99,
}

impl Terminal {
    fn detect(var: &dyn Fn(&str) -> Option<String>) -> Self {
        let term = var("TERM").unwrap_or_default();
        // TERM_PROGRAM names the innermost terminal; tmux sets its own.
        match var("TERM_PROGRAM").as_deref() {
            Some("kgx") => return Self::Console,
            Some("WezTerm") => return Self::WezTerm,
            Some("ghostty") => return Self::Ghostty,
            Some("iTerm.app") => return Self::ITerm2,
            _ => {}
        }
        // TERM survives SSH.
        if term == "xterm-kitty" {
            return Self::Kitty;
        }
        if term == "foot" || term.starts_with("foot-") {
            return Self::Foot;
        }
        if term == "xterm-ghostty" {
            return Self::Ghostty;
        }
        if term == "alacritty" {
            return Self::Alacritty;
        }
        if term == "wezterm" {
            return Self::WezTerm;
        }
        // Inherited into tmux from the terminal that started it.
        let set = |name: &str| var(name).is_some();
        if set("KITTY_WINDOW_ID") {
            Self::Kitty
        } else if set("WEZTERM_PANE") {
            Self::WezTerm
        } else if set("GHOSTTY_RESOURCES_DIR") {
            Self::Ghostty
        } else if set("ITERM_SESSION_ID") {
            Self::ITerm2
        } else if set("KONSOLE_VERSION") {
            Self::Konsole
        } else if set("WT_SESSION") {
            Self::WindowsTerminal
        } else if set("VTE_VERSION") {
            Self::GnomeTerminal
        } else if set("ALACRITTY_WINDOW_ID") {
            Self::Alacritty
        } else {
            Self::Unknown
        }
    }

    fn sequence(self) -> Sequence {
        match self {
            Self::Kitty => Sequence::Osc99,
            Self::Foot | Self::WezTerm | Self::Ghostty | Self::Konsole | Self::Unknown => {
                Sequence::Osc777
            }
            Self::ITerm2 => Sequence::Osc9,
            Self::Console | Self::GnomeTerminal | Self::WindowsTerminal | Self::Alacritty => {
                Sequence::None
            }
        }
    }

    /// The desktop file the notification belongs to.
    fn desktop_entry(self) -> Option<&'static str> {
        match self {
            Self::Console => Some("org.gnome.Console"),
            Self::GnomeTerminal => Some("org.gnome.Terminal"),
            _ => None,
        }
    }
}

/// How this terminal and session raise attention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Profile {
    pub(super) terminal: Terminal,
    pub(super) sequence: Sequence,
    /// Inside tmux: sequences go through its DCS passthrough.
    pub(super) tmux: bool,
    /// Notifications go to the session bus.
    pub(super) desktop: bool,
    pub(super) desktop_entry: Option<&'static str>,
}

/// The `NIX_SECRETS_DESKTOP_NOTIFICATIONS` setting.
pub(super) const DESKTOP_SETTING: &str = "NIX_SECRETS_DESKTOP_NOTIFICATIONS";

impl Profile {
    /// `var` reads the environment; `local_bus` says whether a local
    /// graphical session bus is there; `passthrough` whether tmux passes
    /// sequences on.
    pub(super) fn detect(
        var: &dyn Fn(&str) -> Option<String>,
        local_bus: bool,
        passthrough: impl FnOnce() -> bool,
    ) -> Self {
        let var = |name: &str| var(name).filter(|value| !value.is_empty());
        let terminal = Terminal::detect(&var);
        let tmux = var("TMUX").is_some();
        let mut sequence = terminal.sequence();
        if tmux && sequence != Sequence::None && !passthrough() {
            sequence = Sequence::None;
        }
        let setting = var(DESKTOP_SETTING).unwrap_or_default().to_ascii_lowercase();
        let desktop = local_bus
            && match setting.as_str() {
                "off" | "0" | "no" | "false" => false,
                "always" | "on" | "1" | "yes" | "true" => true,
                // An unknown terminal may honour OSC 777; the bus is sure.
                _ => sequence == Sequence::None || terminal == Terminal::Unknown,
            };
        if desktop && setting != "always" && terminal == Terminal::Unknown {
            sequence = Sequence::None;
        }
        Self {
            terminal,
            sequence,
            tmux,
            desktop,
            desktop_entry: terminal.desktop_entry(),
        }
    }

    /// The profile of the running TUI.
    pub(super) fn current() -> (Self, Option<super::desktop_notify::BusAddress>) {
        let var = |name: &str| std::env::var(name).ok();
        let bus = super::desktop_notify::local_session_bus(&var);
        let profile = Self::detect(&var, bus.is_some(), tmux_passthrough);
        (profile, bus)
    }
}

/// Whether tmux's `allow-passthrough` is on for this pane. Asks tmux, and
/// gives up after half a second.
fn tmux_passthrough() -> bool {
    use std::process::{Command, Stdio};
    let mut command = Command::new("tmux");
    command.args(["show-options", "-pqv"]);
    if let Some(pane) = std::env::var_os("TMUX_PANE") {
        command.arg("-t").arg(pane);
    }
    command.arg("allow-passthrough");
    let ask = |mut command: Command| -> Option<String> {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if child.try_wait().ok()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut output = String::new();
        std::io::Read::read_to_string(&mut child.stdout.take()?, &mut output).ok()?;
        Some(output.trim().to_owned())
    };
    let on = |value: &str| matches!(value, "on" | "all");
    match ask(command).as_deref() {
        Some("") => {
            let mut global = Command::new("tmux");
            global.args(["show-options", "-gqv", "allow-passthrough"]);
            ask(global).as_deref().is_some_and(on)
        }
        Some(value) => on(value),
        None => false,
    }
}

/// What to send after the next frame.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct Signals {
    pub(super) terminal: String,
    pub(super) desktop: Vec<DesktopCall>,
}

impl Signals {
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.terminal.is_empty() && self.desktop.is_empty()
    }
}

/// What has been signalled for a request still open.
#[derive(Debug)]
struct Tracked {
    deadline: Option<Instant>,
    reminded: bool,
}

/// What has been signalled so far.
#[derive(Debug, Default)]
pub(super) struct Attention {
    /// Announced requests that are still open, by key.
    known: BTreeMap<String, Tracked>,
    /// The request whose title is up.
    titled: Option<String>,
    /// Procedures whose missed step was announced, while they show it.
    missed: BTreeSet<String>,
    /// Numbers OSC 99 notifications.
    next_id: u64,
}

/// A request that waits for the operator.
struct Open {
    key: String,
    /// What it is, for the notification.
    what: String,
    /// The window title while it is on screen; `None` in the task bar.
    title: Option<&'static str>,
    deadline: Option<Instant>,
    /// Whether it is announced when first seen: on screen, or flashing.
    announce: bool,
}

/// The request a procedure waits on, as its attention key.
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

/// The request on screen, if any.
fn foreground(model: &crate::model::Model) -> Option<Open> {
    if let Some(prompt) = model.shown_prompt() {
        return Some(Open {
            key: format!("secret:{}", prompt.id),
            what: super::secret_request::dialog_title(prompt),
            title: Some(REQUEST_TITLE),
            deadline: prompt.deadline,
            announce: true,
        });
    }
    let crate::model::Mode::Approval(request) = &model.mode else {
        return None;
    };
    let replacement = !request.host_mutations.is_empty();
    Some(if replacement {
        Open {
            key: format!(
                "host-mutations:{}:{}",
                request.id,
                request.host_mutation_token.as_deref().unwrap_or("missing")
            ),
            what: "Save host-provided changes requested".into(),
            title: Some("(!) nix-secrets: save host-provided changes"),
            deadline: None,
            announce: true,
        }
    } else {
        Open {
            key: format!("deployment:{}", request.id),
            what: "Deployment approval requested".into(),
            title: Some("(!) nix-secrets: deployment approval needed"),
            deadline: None,
            announce: true,
        }
    })
}

fn open_requests(model: &crate::model::Model) -> Vec<Open> {
    let mut open = Vec::new();
    open.extend(foreground(model));
    for procedure in &model.procedures {
        let Some(key) = waiting_request(model, procedure) else {
            continue;
        };
        if open.iter().any(|known| known.key == key) {
            continue;
        }
        open.push(Open {
            key,
            what: format!("{} waits in the task bar", procedure.heading()),
            title: None,
            deadline: procedure.prompts.front().and_then(|prompt| prompt.deadline),
            announce: procedure.flashing,
        });
    }
    open
}

/// ` · denies in 120 s`, while a countdown runs.
fn countdown(deadline: Option<Instant>, now: Instant) -> String {
    deadline.map_or_else(String::new, |deadline| {
        format!(
            " · denies in {} s",
            deadline.saturating_duration_since(now).as_secs_f64().ceil() as u64
        )
    })
}

impl Attention {
    /// What to send after this frame of `model` (`None` when the TUI
    /// closes).
    pub(super) fn update(
        &mut self,
        model: Option<&crate::model::Model>,
        profile: &Profile,
        now: Instant,
    ) -> Signals {
        let mut signals = Signals::default();
        let open = model.map(open_requests).unwrap_or_default();
        let on_screen = open
            .iter()
            .find(|request| request.title.is_some())
            .map(|request| request.key.clone());
        if self.titled.is_some() && self.titled != on_screen {
            self.titled = None;
            signals.terminal.push_str(&restore());
        }
        for request in &open {
            let remaining = request
                .deadline
                .map_or(Duration::MAX, |deadline| deadline.saturating_duration_since(now));
            match self.known.get_mut(&request.key) {
                None if request.announce => {
                    self.known.insert(
                        request.key.clone(),
                        Tracked {
                            deadline: request.deadline,
                            // A late request does not get its reminder at once.
                            reminded: remaining <= REMINDER_AT,
                        },
                    );
                    let summary = "nix-secrets: approval needed";
                    let body = format!("{}{}", request.what, countdown(request.deadline, now));
                    self.notify(&mut signals, profile, &request.key, summary, &body);
                }
                None => {}
                Some(tracked) => {
                    let started = match (tracked.deadline, request.deadline) {
                        (None, Some(_)) => true,
                        (Some(old), Some(new)) => new > old + Duration::from_secs(1),
                        _ => false,
                    };
                    tracked.deadline = request.deadline;
                    if started {
                        tracked.reminded = remaining <= REMINDER_AT;
                        let body = format!("{}{}", request.what, countdown(request.deadline, now));
                        self.notify(
                            &mut signals,
                            profile,
                            &request.key,
                            "nix-secrets: countdown started",
                            &body,
                        );
                    } else if !tracked.reminded && remaining <= REMINDER_AT {
                        tracked.reminded = true;
                        let summary = format!(
                            "nix-secrets: {} s left to answer",
                            remaining.as_secs_f64().ceil() as u64
                        );
                        let what = request.what.clone();
                        self.notify(&mut signals, profile, &request.key, &summary, &what);
                    }
                }
            }
            if let Some(title) = request.title {
                if self.titled.is_none() && self.known.contains_key(&request.key) {
                    self.titled = Some(request.key.clone());
                    signals.terminal.push_str(&set_title(title));
                }
            }
        }
        let still_open = open.iter().map(|request| &request.key).collect::<BTreeSet<_>>();
        let closed = self
            .known
            .keys()
            .filter(|key| !still_open.contains(key))
            .cloned()
            .collect::<Vec<_>>();
        for key in closed {
            self.known.remove(&key);
            if profile.desktop {
                signals.desktop.push(DesktopCall::Close { key });
            }
        }
        self.update_missed(model, profile, &mut signals);
        signals
    }

    /// A procedure step that timed out or failed, once per procedure.
    fn update_missed(
        &mut self,
        model: Option<&crate::model::Model>,
        profile: &Profile,
        signals: &mut Signals,
    ) {
        let mut current = BTreeSet::new();
        for procedure in model.map_or(&[][..], |model| &model.procedures) {
            let Some(step) = procedure.missed_step() else {
                continue;
            };
            if step.outcome == crate::model::StepOutcome::Denied {
                continue;
            }
            let key = format!("missed:{}", procedure.id);
            current.insert(key.clone());
            if self.missed.insert(key.clone()) {
                let summary = format!("nix-secrets: step {}", step.outcome.verb());
                let body = format!(
                    "{} {}",
                    procedure.title,
                    step.missed().expect("a missed step")
                );
                self.notify(signals, profile, &key, &summary, &body);
            }
        }
        let gone = self
            .missed
            .difference(&current)
            .cloned()
            .collect::<Vec<_>>();
        for key in gone {
            self.missed.remove(&key);
            if profile.desktop {
                signals.desktop.push(DesktopCall::Close { key });
            }
        }
    }

    /// BEL and one notification for `key`.
    fn notify(&mut self, signals: &mut Signals, profile: &Profile, key: &str, summary: &str, body: &str) {
        let summary = clean(summary);
        let body = clean(body);
        signals.terminal.push_str(BEL);
        let sequence = match profile.sequence {
            Sequence::None => String::new(),
            Sequence::Osc777 => format!(
                "\x1b]777;notify;{};{}\x07",
                summary.replace(';', ","),
                body.replace(';', ",")
            ),
            Sequence::Osc9 => format!("\x1b]9;{summary}: {body}\x07"),
            Sequence::Osc99 => {
                self.next_id += 1;
                let id = format!("nix-secrets-{}", self.next_id);
                format!(
                    "\x1b]99;i={id}:d=0:u=2;{summary}\x1b\\\x1b]99;i={id}:p=body;{body}\x1b\\"
                )
            }
        };
        if !sequence.is_empty() {
            signals.terminal.push_str(&passthrough(&sequence, profile.tmux));
        }
        if profile.terminal == Terminal::ITerm2 {
            signals.terminal.push_str(&passthrough(
                "\x1b]1337;RequestAttention=yes\x07",
                profile.tmux,
            ));
        }
        if profile.desktop {
            signals.desktop.push(DesktopCall::Notify {
                key: key.to_owned(),
                summary,
                body,
            });
        }
    }
}

/// Without control characters, which could end a sequence early or start
/// another one (names come from /proc), and at most [`MAX_TEXT`] long.
fn clean(text: &str) -> String {
    let mut text: String = text.chars().filter(|c| !c.is_control()).collect();
    if text.chars().count() > MAX_TEXT {
        text = text.chars().take(MAX_TEXT - 1).collect();
        text.push('…');
    }
    text
}

fn set_title(title: &str) -> String {
    format!("{PUSH_TITLE}\x1b]2;{}\x07", clean(title))
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
mod tests;
