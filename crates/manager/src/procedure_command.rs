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
use crate::with_secrets::{connect_backend, Options};
use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::procedure::{MAX_DECLARED_STEPS, PROCEDURE_ENVIRONMENT};
use nix_secrets_core::{Request, Response};
use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

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
}
