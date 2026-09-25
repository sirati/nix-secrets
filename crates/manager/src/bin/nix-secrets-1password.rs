//! Runs one age decryption with exactly one 1Password authorization.
//!
//! age-plugin-1p starts `op item list | op item get -` as two concurrent
//! processes. In a session that 1Password has not authorized yet, each of them
//! raises its own prompt; rejecting one leaves the other to fail even when it
//! is approved. This launcher therefore authorizes first with a single `op`
//! call and only then runs age, whose `op` calls reuse that authorization.
//!
//! By default it also leads a new session without a controlling terminal.
//! The 1Password app binds such an authorization to the session leader and
//! names that executable in its prompt, so one approval covers exactly this
//! run and the prompt reads "nix-secrets-1password". `--shared-session`
//! keeps the caller's terminal session and its 10-minute authorization.
#![forbid(unsafe_code)]

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitCode, ExitStatus, Stdio};

/// Exit status when 1Password did not authorize; age itself never uses it.
const NOT_AUTHORIZED: u8 = 77;
const MESSAGE_BYTES: u64 = 4096;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1).peekable();
    let shared = arguments
        .next_if(|argument| argument == "--shared-session")
        .is_some();
    let Some(program) = arguments.next() else {
        eprintln!("usage: nix-secrets-1password [--shared-session] PROGRAM [ARGUMENT...]");
        return ExitCode::from(2);
    };
    if !shared {
        if let Err(error) = rustix::process::setsid() {
            eprintln!("nix-secrets-1password: could not start a new session: {error}");
            return ExitCode::from(125);
        }
    }
    if let Err(message) = authorize() {
        eprintln!("nix-secrets-1password: {message}");
        return ExitCode::from(NOT_AUTHORIZED);
    }
    match Command::new(&program).args(arguments).status() {
        Ok(status) => exit_code(status),
        Err(error) => {
            eprintln!(
                "nix-secrets-1password: could not run {}: {error}",
                program.to_string_lossy()
            );
            ExitCode::from(127)
        }
    }
}

/// Asks 1Password once. `op vault list` needs an authorized session and
/// prints only vault names, which are discarded.
fn authorize() -> Result<(), String> {
    let mut child = Command::new("op")
        .args(["vault", "list", "--format=json"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("1Password CLI could not be started: op: {error}"))?;
    let mut message = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(MESSAGE_BYTES).read_to_end(&mut message);
    }
    let status = child
        .wait()
        .map_err(|error| format!("1Password CLI failed: {error}"))?;
    if status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&message);
    let message = message
        .lines()
        .map(|line| strip_log_prefix(line.trim()))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Err(format!("1Password authorization failed: {message}"))
}

/// op prefixes errors with `[ERROR] YYYY/MM/DD HH:MM:SS `.
fn strip_log_prefix(line: &str) -> &str {
    match line.strip_prefix("[ERROR] ") {
        Some(rest) if rest.len() > 20 => &rest[20..],
        _ => line,
    }
}

fn exit_code(status: ExitStatus) -> ExitCode {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitCode::from(code as u8),
        (None, Some(signal)) => ExitCode::from(128 + signal as u8),
        (None, None) => ExitCode::FAILURE,
    }
}
