//! `nix-secrets procedure`: runs a command as one procedure, so the
//! operator sees all of its prompts in one dialog with a common title.
//!
//! ```text
//! nix-secrets procedure [--repository PATH] [--backend-socket PATH] --title TEXT [--steps N] -- COMMAND [ARGUMENT...]
//! ```
//!
//! The backend registers the procedure for this process and answers with a
//! token, which the command receives in `NIX_SECRETS_PROCEDURE`. Every
//! `nix-secrets` requester it starts (`with-ssh-agent`, `with-secrets`,
//! `pipe-secret`, `sign-artifacts`, `sign-closure`, `deploy`) sends the
//! token, and the backend accepts it only from descendants of this process.
//! The procedure ends when the command exits. Without a reachable backend
//! the command still runs, and its prompts appear one by one.
//!
//! ```text
//! nix-secrets procedure-step-failed [--repository PATH] [--backend-socket PATH] --label TEXT --reason TEXT
//! ```
//!
//! Inside the command, reports that the step `--label` failed. The TUI
//! shows it in the procedure dialog as a failed step with the reason; a
//! second report with the same label updates that step.
//!
//! ```text
//! nix-secrets procedure-step-warning [--repository PATH] [--backend-socket PATH] --label TEXT --reason TEXT
//! ```
//!
//! Reports that the step worked with a caveat, the same way. The TUI lists
//! it with ⚠, and a procedure that succeeds with warnings stays until the
//! operator closes its result.
use crate::socket::connect_verified;
use crate::with_secrets::{backend_candidates, connect_backend, Options};
use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::procedure::{clean_text, MAX_DECLARED_STEPS, PROCEDURE_ENVIRONMENT};
use nix_secrets_core::{Request, Response};
use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const USAGE: &str = "usage: nix-secrets procedure [--repository PATH] [--backend-socket PATH] \
--title TEXT [--steps N] -- COMMAND [ARGUMENT...]";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub options: Options,
    pub title: String,
    pub steps: Option<u32>,
    pub command: Vec<OsString>,
}

pub fn parse(
    arguments: impl IntoIterator<Item = OsString>,
    working_directory: PathBuf,
) -> Result<Invocation, String> {
    let mut arguments = arguments.into_iter();
    let mut options = Options {
        repository: working_directory,
        ..Options::default()
    };
    let mut title = None;
    let mut steps = None;
    let mut command = None;
    while let Some(argument) = arguments.next() {
        let text = argument
            .to_str()
            .ok_or_else(|| format!("unexpected argument {argument:?}; {USAGE}"))?
            .to_owned();
        let mut value = |name: &str| {
            arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(|| format!("{name} requires UTF-8 text; {USAGE}"))
        };
        match text.as_str() {
            "--" => {
                command = Some(arguments.by_ref().collect::<Vec<_>>());
                break;
            }
            "--title" => title = Some(value("--title")?),
            "--steps" => {
                let count = value("--steps")?
                    .parse::<u32>()
                    .ok()
                    .filter(|count| (1..=MAX_DECLARED_STEPS).contains(count))
                    .ok_or_else(|| {
                        format!("--steps takes a number from 1 to {MAX_DECLARED_STEPS}")
                    })?;
                steps = Some(count);
            }
            "--repository" => options.repository = value("--repository")?.into(),
            "--backend-socket" => options.backend_socket = Some(value("--backend-socket")?.into()),
            _ => return Err(format!("unexpected argument {text:?}; {USAGE}")),
        }
    }
    let title = title
        .filter(|title| !title.trim().is_empty())
        .ok_or_else(|| format!("name the procedure with --title; {USAGE}"))?;
    let command = command
        .filter(|command| !command.is_empty())
        .ok_or_else(|| format!("`--` must be followed by a command; {USAGE}"))?;
    Ok(Invocation {
        options,
        title,
        steps,
        command,
    })
}

/// Registers the procedure; the connection holds it open.
fn begin(
    options: &Options,
    runtime: &Path,
    title: &str,
    steps: Option<u32>,
) -> Result<(UnixStream, String), String> {
    let mut stream = connect_backend(options, runtime)
        .map_err(|error| error.replace(" (or pass --local to decrypt here)", ""))?;
    write_json(
        &mut stream,
        &Request::BeginProcedure {
            title: title.to_owned(),
            steps,
        },
    )
    .map_err(|error| error.to_string())?;
    match read_json::<Response>(&mut stream).map_err(|error| error.to_string())? {
        Some(Response::ProcedureBegun { token, .. }) => Ok((stream, token)),
        Some(Response::Error { message }) => Err(message),
        Some(other) => Err(format!("unexpected backend response: {other:?}")),
        // A backend without procedure support closes the connection.
        None => Err("the backend does not support procedures".into()),
    }
}

/// Runs the command inside the procedure and ends it when the command
/// exits. Returns the command's status.
pub fn run(
    invocation: &Invocation,
    runtime: &Path,
) -> Result<std::process::ExitStatus, String> {
    let (program, arguments) = invocation
        .command
        .split_first()
        .expect("parse requires a command");
    let mut command = std::process::Command::new(program);
    command.args(arguments);
    let registration = begin(
        &invocation.options,
        runtime,
        &invocation.title,
        invocation.steps,
    );
    match &registration {
        Ok((_, token)) => {
            command.env(PROCEDURE_ENVIRONMENT, token);
        }
        Err(error) => eprintln!(
            "nix-secrets: no procedure for {:?}: {error}; its prompts appear one by one",
            invocation.title
        ),
    }
    let status = command
        .status()
        .map_err(|error| format!("cannot run {program:?}: {error}"));
    if let Ok((mut stream, _)) = registration {
        // Closing the connection ends it as well; asking first lets the
        // TUI drop the entry before this command returns.
        // The TUI shows how the command ended in the procedure dialog.
        let exit_code = status.as_ref().ok().map(shell_exit_code).unwrap_or(Some(127));
        if write_json(&mut stream, &Request::EndProcedure { exit_code }).is_ok() {
            let _ = read_json::<Response>(&mut stream);
        }
    }
    status
}

/// What `procedure-step-failed` and `procedure-step-warning` report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepReportKind {
    Failed,
    Warning,
}

impl StepReportKind {
    /// The subcommand that reports it.
    pub fn command(self) -> &'static str {
        match self {
            Self::Failed => "procedure-step-failed",
            Self::Warning => "procedure-step-warning",
        }
    }

    /// `failed`, as in `nix-secrets: step failed: LABEL: REASON`.
    fn word(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Warning => "warning",
        }
    }

    pub fn usage(self) -> String {
        format!(
            "usage: nix-secrets {} [--repository PATH] [--backend-socket PATH] --label TEXT \
             --reason TEXT",
            self.command()
        )
    }
}

/// How long a step report waits for the backend before giving up.
pub const STEP_REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// `nix-secrets procedure-step-failed` or `procedure-step-warning`: the
/// command of a procedure reports that a step failed, or worked with a
/// caveat, and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepReport {
    pub kind: StepReportKind,
    pub options: Options,
    pub label: String,
    pub reason: String,
}

pub fn parse_step_report(
    kind: StepReportKind,
    arguments: impl IntoIterator<Item = OsString>,
    working_directory: PathBuf,
) -> Result<StepReport, String> {
    let usage = kind.usage();
    let mut arguments = arguments.into_iter();
    let mut options = Options {
        repository: working_directory,
        ..Options::default()
    };
    let (mut label, mut reason) = (None, None);
    while let Some(argument) = arguments.next() {
        let text = argument
            .to_str()
            .ok_or_else(|| format!("unexpected argument {argument:?}; {usage}"))?
            .to_owned();
        let mut value = |name: &str| {
            arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(|| format!("{name} requires UTF-8 text; {usage}"))
        };
        match text.as_str() {
            "--label" => label = Some(value("--label")?),
            "--reason" => reason = Some(value("--reason")?),
            "--repository" => options.repository = value("--repository")?.into(),
            "--backend-socket" => options.backend_socket = Some(value("--backend-socket")?.into()),
            _ => return Err(format!("unexpected argument {text:?}; {usage}")),
        }
    }
    let label = label
        .filter(|label| !label.trim().is_empty())
        .ok_or_else(|| format!("name the step with --label; {usage}"))?;
    let reason = reason
        .filter(|reason| !reason.trim().is_empty())
        .ok_or_else(|| format!("give the reason with --reason; {usage}"))?;
    Ok(StepReport {
        kind,
        options,
        label,
        reason,
    })
}

/// A running backend for the procedure: the one it registered with is
/// already running, so this never starts one.
fn connect_running(options: &Options, runtime: &Path) -> Result<UnixStream, String> {
    if let Some(socket) = &options.backend_socket {
        return connect_verified(socket)
            .map_err(|error| format!("cannot connect to {}: {error}", socket.display()));
    }
    backend_candidates(runtime, &options.repository)
        .iter()
        .find_map(|socket| connect_verified(socket).ok())
        .ok_or_else(|| "no nix-secrets backend is running for this repository".into())
}

/// Sends the report; `Ok(Err(..))` is the backend refusing it.
fn send_report(
    report: &StepReport,
    runtime: &Path,
    token: String,
    timeout: Duration,
) -> Result<Result<(), String>, String> {
    let mut stream = connect_running(&report.options, runtime)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| error.to_string())?;
    let (procedure, label, reason) = (token, report.label.clone(), report.reason.clone());
    let request = match report.kind {
        StepReportKind::Failed => Request::FailProcedureStep {
            procedure,
            label,
            reason,
        },
        StepReportKind::Warning => Request::WarnProcedureStep {
            procedure,
            label,
            reason,
        },
    };
    write_json(&mut stream, &request).map_err(|error| error.to_string())?;
    match read_json::<Response>(&mut stream).map_err(|error| error.to_string())? {
        Some(Response::Success) => Ok(Ok(())),
        Some(Response::Error { message }) => Ok(Err(message)),
        Some(other) => Ok(Err(format!("unexpected backend response: {other:?}"))),
        None => Ok(Err("the backend closed the connection without an answer".into())),
    }
}

/// Reports a failed or warned step to the TUI. The report is always
/// printed first, so it is never hidden; a missing token or an unreachable
/// backend only adds a note and exits 0. A backend that refuses the report
/// exits 1.
pub fn report_step(
    report: &StepReport,
    runtime: &Path,
    token: Option<String>,
    timeout: Duration,
    stderr: &mut dyn std::io::Write,
) -> i32 {
    let shown = |text: &str| clean_text(text, usize::MAX);
    let _ = writeln!(
        stderr,
        "nix-secrets: step {}: {}: {}",
        report.kind.word(),
        shown(&report.label),
        shown(&report.reason)
    );
    let Some(token) = token else {
        let _ = writeln!(
            stderr,
            "nix-secrets: not inside `nix-secrets procedure` ({PROCEDURE_ENVIRONMENT} is unset); \
             the TUI was not reached"
        );
        return 0;
    };
    match send_report(report, runtime, token, timeout) {
        Ok(Ok(())) => 0,
        Ok(Err(message)) => {
            let _ = writeln!(stderr, "nix-secrets: the backend refused the report: {message}");
            1
        }
        Err(error) => {
            let _ = writeln!(stderr, "nix-secrets: {error}; the TUI was not reached");
            0
        }
    }
}

/// The exit code as a shell reports it: 128 + the signal that ended it.
fn shell_exit_code(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_title_steps_and_command() {
        let parsed = parse(
            os(&[
                "--title",
                "Update ns1",
                "--steps",
                "4",
                "--backend-socket",
                "/b.sock",
                "--",
                "nix-update-remote",
                "--title",
            ]),
            "/cwd".into(),
        )
        .unwrap();
        assert_eq!(parsed.title, "Update ns1");
        assert_eq!(parsed.steps, Some(4));
        assert_eq!(parsed.options.backend_socket, Some(PathBuf::from("/b.sock")));
        assert_eq!(parsed.command, os(&["nix-update-remote", "--title"]));
        assert!(parse(os(&["--", "x"]), "/".into()).is_err(), "no title");
        assert!(parse(os(&["--title", " ", "--", "x"]), "/".into()).is_err());
        assert!(parse(os(&["--title", "t"]), "/".into()).is_err(), "no command");
        assert!(parse(os(&["--title", "t", "--steps", "0", "--", "x"]), "/".into()).is_err());
        assert!(parse(os(&["--title", "t", "--local", "--", "x"]), "/".into()).is_err());
    }

    #[test]
    fn parses_failed_and_warned_step_reports() {
        for kind in [StepReportKind::Failed, StepReportKind::Warning] {
            parses_a_step_report(kind, |arguments, cwd| parse_step_report(kind, arguments, cwd));
        }
    }

    fn parses_a_step_report(
        kind: StepReportKind,
        parse_step_failed: impl Fn(Vec<OsString>, PathBuf) -> Result<StepReport, String>,
    ) {
        let parsed = parse_step_failed(
            os(&[
                "--label",
                "activate ns1",
                "--reason",
                "rolled back",
                "--backend-socket",
                "/b.sock",
            ]),
            "/cwd".into(),
        )
        .unwrap();
        assert_eq!(parsed.label, "activate ns1");
        assert_eq!(parsed.kind, kind);
        assert_eq!(parsed.reason, "rolled back");
        assert_eq!(parsed.options.repository, PathBuf::from("/cwd"));
        assert_eq!(parsed.options.backend_socket, Some(PathBuf::from("/b.sock")));
        let repository =
            parse_step_failed(os(&["--repository", "/r", "--label", "l", "--reason", "r"]), "/".into())
                .unwrap();
        assert_eq!(repository.options.repository, PathBuf::from("/r"));
        assert!(parse_step_failed(os(&["--reason", "r"]), "/".into()).is_err(), "no label");
        assert!(parse_step_failed(os(&["--label", " ", "--reason", "r"]), "/".into()).is_err());
        assert!(parse_step_failed(os(&["--label", "l"]), "/".into()).is_err(), "no reason");
        assert!(parse_step_failed(os(&["--label", "l", "--reason"]), "/".into()).is_err());
        assert!(
            parse_step_failed(os(&["--label", "l", "--reason", "r", "--", "x"]), "/".into()).is_err()
        );
    }

    #[test]
    fn a_step_report_is_always_printed_and_never_fails_for_lack_of_a_tui() {
        for (kind, word) in [(StepReportKind::Failed, "failed"), (StepReportKind::Warning, "warning")] {
            report_is_always_printed(kind, word);
        }
    }

    fn report_is_always_printed(kind: StepReportKind, word: &str) {
        let temp = tempfile::tempdir().unwrap();
        let failure = StepReport {
            kind,
            options: Options {
                repository: temp.path().into(),
                backend_socket: Some(temp.path().join("missing.sock")),
                ..Options::default()
            },
            label: "activate ns1".into(),
            reason: "rolled back\x1b[2J".into(),
        };
        let report = |token: Option<&str>| {
            let mut stderr = Vec::new();
            let code = report_step(
                &failure,
                temp.path(),
                token.map(str::to_owned),
                STEP_REPORT_TIMEOUT,
                &mut stderr,
            );
            (code, String::from_utf8(stderr).unwrap())
        };
        let (code, stderr) = report(None);
        assert_eq!(code, 0);
        assert!(
            stderr.starts_with(&format!("nix-secrets: step {word}: activate ns1: rolled back [2J\n")),
            "{stderr}"
        );
        assert!(stderr.contains("the TUI was not reached"), "{stderr}");
        let (code, stderr) = report(Some("proc-1-ab:secret"));
        assert_eq!(code, 0);
        assert!(stderr.starts_with(&format!("nix-secrets: step {word}: activate ns1:")), "{stderr}");
        assert!(stderr.contains("missing.sock"), "{stderr}");
        assert!(stderr.contains("the TUI was not reached"), "{stderr}");
    }

    #[test]
    fn a_step_report_waits_for_a_silent_backend_only_briefly() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("silent.sock");
        // Accepts and reads, but never answers.
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let silent = std::thread::spawn(move || {
            let connection = listener.accept().unwrap().0;
            std::thread::sleep(Duration::from_secs(3));
            drop(connection);
        });
        let failure = StepReport {
            kind: StepReportKind::Warning,
            options: Options {
                backend_socket: Some(socket),
                ..Options::default()
            },
            label: "activate ns1".into(),
            reason: "rolled back".into(),
        };
        let started = std::time::Instant::now();
        let mut stderr = Vec::new();
        let code = report_step(
            &failure,
            temp.path(),
            Some("proc-1-ab:secret".into()),
            Duration::from_millis(300),
            &mut stderr,
        );
        let stderr = String::from_utf8(stderr).unwrap();
        assert_eq!(code, 0, "{stderr}");
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(stderr.contains("the TUI was not reached"), "{stderr}");
        silent.join().unwrap();
    }
}
