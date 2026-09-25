//! Runs one age invocation as the leader of a new session without a
//! controlling terminal.
//!
//! The 1Password app binds a CLI authorization made without a terminal to the
//! session leader and names that leader's executable in its prompt. Leading
//! the session makes each authorization last for exactly this one run and
//! makes the prompt read "nix-secrets-1password".
#![forbid(unsafe_code)]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let Some(program) = arguments.next() else {
        eprintln!("usage: nix-secrets-1password PROGRAM [ARGUMENT...]");
        return ExitCode::from(2);
    };
    if let Err(error) = rustix::process::setsid() {
        eprintln!("nix-secrets-1password: could not start a new session: {error}");
        return ExitCode::from(125);
    }
    match Command::new(&program).args(arguments).status() {
        Ok(status) => match (status.code(), status.signal()) {
            (Some(code), _) => ExitCode::from(code as u8),
            (None, Some(signal)) => ExitCode::from(128 + signal as u8),
            (None, None) => ExitCode::FAILURE,
        },
        Err(error) => {
            eprintln!(
                "nix-secrets-1password: could not run {}: {error}",
                program.to_string_lossy()
            );
            ExitCode::from(127)
        }
    }
}
