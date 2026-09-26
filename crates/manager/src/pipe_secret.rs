//! `nix-secrets pipe-secret`: hands one decrypted value to another program
//! without writing it to disk or showing it.
//!
//! - `pipe-secret [OPTIONS] <identifier> -- <command...>` runs the command
//!   with the value on its stdin and exits with the command's status.
//! - `pipe-secret [OPTIONS] <identifier>` writes the value to stdout for a
//!   pipeline and refuses when stdout is a terminal.
//!
//! The value exists only in this process's memory and in the pipe.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipeInvocation {
    /// Repository holding `nix-secrets.toml`; defaults to the working
    /// directory, like the consumer flake's `nix run`.
    pub repository: PathBuf,
    pub identity: Option<PathBuf>,
    pub shared_session: bool,
    /// Connect to this backend socket instead of starting the repository's.
    pub backend_socket: Option<PathBuf>,
    /// Read the evaluated schema from this JSON file instead of `nix eval`.
    pub schema_file: Option<PathBuf>,
    pub identifier: String,
    /// `None` writes the value to stdout.
    pub command: Option<Vec<OsString>>,
}

pub const USAGE: &str = "usage: nix-secrets pipe-secret [--repository PATH] [--secret-identity PATH] \
[--1password-shared-session] [--backend-socket PATH --schema-file PATH] IDENTIFIER [-- COMMAND [ARGUMENT...]]";

pub fn parse(
    arguments: impl IntoIterator<Item = OsString>,
    working_directory: PathBuf,
) -> Result<PipeInvocation, String> {
    let mut arguments = arguments.into_iter();
    let mut repository = None;
    let mut identity = None;
    let mut shared_session = false;
    let mut backend_socket = None;
    let mut schema_file = None;
    let mut identifier = None;
    let mut command = None;
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--") => {
                let rest = arguments.by_ref().collect::<Vec<_>>();
                if rest.is_empty() {
                    return Err("`--` must be followed by a command".into());
                }
                command = Some(rest);
                break;
            }
            Some("--repository") if identifier.is_none() => {
                repository = Some(PathBuf::from(
                    arguments.next().ok_or("--repository requires a path")?,
                ));
            }
            Some("--secret-identity") if identifier.is_none() => {
                identity = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--secret-identity requires a path")?,
                ));
            }
            Some("--1password-shared-session") if identifier.is_none() => shared_session = true,
            Some("--backend-socket") if identifier.is_none() => {
                backend_socket = Some(PathBuf::from(
                    arguments.next().ok_or("--backend-socket requires a path")?,
                ));
            }
            Some("--schema-file") if identifier.is_none() => {
                schema_file = Some(PathBuf::from(
                    arguments.next().ok_or("--schema-file requires a path")?,
                ));
            }
            Some(value) if identifier.is_none() && !value.starts_with('-') => {
                identifier = Some(value.to_owned());
            }
            _ => return Err(format!("unexpected argument {argument:?}; {USAGE}")),
        }
    }
    if backend_socket.is_some() != schema_file.is_some() {
        return Err("--backend-socket and --schema-file are used together".into());
    }
    Ok(PipeInvocation {
        repository: repository.unwrap_or(working_directory),
        identity,
        shared_session,
        backend_socket,
        schema_file,
        identifier: identifier.ok_or(USAGE)?,
        command,
    })
}

/// Where the value goes.
pub enum Sink<'a> {
    Command(&'a [OsString]),
    /// Standard output, with whether it is a terminal.
    Stdout {
        output: &'a mut dyn Write,
        is_terminal: bool,
    },
}

/// Delivers `value`. Returns the command's status for the wrapper form.
pub fn deliver(value: &[u8], sink: Sink<'_>) -> Result<Option<ExitStatus>, String> {
    match sink {
        Sink::Stdout {
            output,
            is_terminal,
        } => {
            if is_terminal {
                return Err(
                    "refusing to write a secret to a terminal; pipe stdout into a program or use `-- COMMAND`"
                        .into(),
                );
            }
            write_ignoring_early_close(output, value)
                .map_err(|error| format!("cannot write the value to stdout: {error}"))?;
            Ok(None)
        }
        Sink::Command(argv) => {
            let (program, arguments) = argv.split_first().ok_or("empty command")?;
            let mut child = Command::new(program)
                .args(arguments)
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|error| format!("cannot start {program:?}: {error}"))?;
            let mut stdin = child.stdin.take().expect("stdin is piped");
            let written = write_ignoring_early_close(&mut stdin, value);
            drop(stdin);
            let status = child
                .wait()
                .map_err(|error| format!("cannot wait for {program:?}: {error}"))?;
            written.map_err(|error| format!("cannot write the value to {program:?}: {error}"))?;
            Ok(Some(status))
        }
    }
}

/// A reader that stops early (for example after reading one line) is its
/// own business; only other write failures are errors.
fn write_ignoring_early_close(output: &mut dyn Write, value: &[u8]) -> io::Result<()> {
    match output.write_all(value).and_then(|()| output.flush()) {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_both_forms() {
        let wrapper = parse(
            os(&[
                "--repository",
                "/repo",
                "host.services.a.key",
                "--",
                "sign",
                "--key-stdin",
            ]),
            "/cwd".into(),
        )
        .unwrap();
        assert_eq!(wrapper.repository, PathBuf::from("/repo"));
        assert_eq!(wrapper.identifier, "host.services.a.key");
        assert_eq!(wrapper.command, Some(os(&["sign", "--key-stdin"])));
        let producer = parse(os(&["host.services.a.key"]), "/cwd".into()).unwrap();
        assert_eq!(producer.repository, PathBuf::from("/cwd"));
        assert_eq!(producer.command, None);
        assert!(parse(os(&[]), "/".into()).is_err());
        assert!(parse(os(&["a", "b"]), "/".into()).is_err());
        assert!(parse(os(&["a", "--"]), "/".into()).is_err());
        assert!(parse(os(&["--unknown", "a"]), "/".into()).is_err());
    }

    #[test]
    fn wrapper_delivers_exact_bytes_on_stdin_and_returns_the_status() {
        let temp = tempfile::tempdir().unwrap();
        let out = temp.path().join("received");
        let value = b"line one\n\0binary\xff tail";
        let status = deliver(
            value,
            Sink::Command(&os(&[
                "sh",
                "-c",
                &format!("cat > '{}'; exit 3", out.display()),
            ])),
        )
        .unwrap()
        .unwrap();
        assert_eq!(status.code(), Some(3));
        assert_eq!(std::fs::read(&out).unwrap(), value);
        // A command that stops reading early is not an error.
        let status = deliver(&vec![b'x'; 1 << 20], Sink::Command(&os(&["true"])))
            .unwrap()
            .unwrap();
        assert!(status.success());
        assert!(deliver(b"x", Sink::Command(&os(&["/nonexistent/program"]))).is_err());
        let _ = ExitStatus::from_raw(0);
    }

    #[test]
    fn producer_writes_only_the_value_and_refuses_a_terminal() {
        let mut output = Vec::new();
        assert_eq!(
            deliver(
                b"secret\x00bytes",
                Sink::Stdout {
                    output: &mut output,
                    is_terminal: false
                }
            )
            .unwrap(),
            None
        );
        assert_eq!(output, b"secret\x00bytes");
        let mut screen = Vec::new();
        let error = deliver(
            b"secret",
            Sink::Stdout {
                output: &mut screen,
                is_terminal: true,
            },
        )
        .unwrap_err();
        assert!(error.contains("terminal"));
        assert!(screen.is_empty());
    }
}
