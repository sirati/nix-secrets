//! `nix-secrets with-secrets`: asks the attached TUI for a batch of values,
//! runs a command that fetches them with `pipe-secret`, and ends the
//! session when the command exits.
//!
//! ```text
//! nix-secrets with-secrets [OPTIONS] IDENTIFIER... -- COMMAND [ARGUMENT...]
//! ```
//!
//! The request goes to the backend of the repository, which forwards it to
//! the most recently attached TUI. After the operator approves there, the
//! TUI decrypts every value with one 1Password authorization and the
//! backend serves them on a private socket named by `NIX_SECRETS_SESSION`
//! in the command's environment. `--local` instead decrypts here, again with
//! one authorization, and serves the session from this process.
use crate::socket::connect_verified;
use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{Request, Response};
use std::ffi::OsString;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Options {
    /// Repository holding `nix-secrets.toml`; defaults to the working
    /// directory, like the consumer flake's `nix run`.
    pub repository: PathBuf,
    /// Connect to this backend socket instead of the repository's.
    pub backend_socket: Option<PathBuf>,
    /// Decrypt in this process instead of asking the TUI.
    pub local: bool,
    pub identity: Option<PathBuf>,
    pub shared_session: bool,
    /// Read the evaluated schema from this JSON file instead of `nix eval`.
    pub schema_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub options: Options,
    pub identifiers: Vec<String>,
    pub command: Vec<OsString>,
}

pub const USAGE: &str =
    "usage: nix-secrets with-secrets [--repository PATH] [--backend-socket PATH] \
[--local [--secret-identity PATH] [--1password-shared-session] [--schema-file PATH]] \
IDENTIFIER... -- COMMAND [ARGUMENT...]";

/// Reads one option shared with `pipe-secret`. Returns whether it was one.
pub fn parse_option(
    argument: &str,
    arguments: &mut impl Iterator<Item = OsString>,
    options: &mut Options,
) -> Result<bool, String> {
    let mut path = |name: &str| {
        arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| format!("{name} requires a path"))
    };
    match argument {
        "--repository" => options.repository = path("--repository")?,
        "--backend-socket" => options.backend_socket = Some(path("--backend-socket")?),
        "--secret-identity" => options.identity = Some(path("--secret-identity")?),
        "--schema-file" => options.schema_file = Some(path("--schema-file")?),
        "--1password-shared-session" => options.shared_session = true,
        "--local" => options.local = true,
        _ => return Ok(false),
    }
    Ok(true)
}

/// Checks that local-only options come with `--local`.
pub fn check_options(options: &Options) -> Result<(), String> {
    if !options.local
        && (options.identity.is_some() || options.shared_session || options.schema_file.is_some())
    {
        return Err(
            "--secret-identity, --1password-shared-session and --schema-file decrypt in this \
             process and require --local"
                .into(),
        );
    }
    if options.local && options.schema_file.is_some() && options.backend_socket.is_none() {
        return Err("--schema-file is used together with --backend-socket".into());
    }
    Ok(())
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
    let mut identifiers = Vec::new();
    let mut command = None;
    while let Some(argument) = arguments.next() {
        let text = argument
            .to_str()
            .ok_or_else(|| format!("unexpected argument {argument:?}; {USAGE}"))?
            .to_owned();
        if text == "--" {
            command = Some(arguments.by_ref().collect::<Vec<_>>());
            break;
        }
        if identifiers.is_empty() && parse_option(&text, &mut arguments, &mut options)? {
            continue;
        }
        if text.starts_with('-') {
            return Err(format!("unexpected argument {text:?}; {USAGE}"));
        }
        if identifiers.contains(&text) {
            return Err(format!("{text} is listed twice"));
        }
        identifiers.push(text);
    }
    check_options(&options)?;
    let command = command
        .filter(|command| !command.is_empty())
        .ok_or_else(|| format!("`--` must be followed by a command; {USAGE}"))?;
    if identifiers.is_empty() {
        return Err(format!("name at least one identifier; {USAGE}"));
    }
    Ok(Invocation {
        options,
        identifiers,
        command,
    })
}

/// The backend sockets that may serve `repository`, as the TUI names them:
/// its path as given (made absolute) and its canonical path.
pub fn backend_candidates(runtime: &Path, repository: &Path) -> Vec<PathBuf> {
    let directory = runtime.join("nix-secrets");
    let mut paths = Vec::new();
    if let Ok(absolute) = std::path::absolute(repository) {
        paths.push(absolute);
    }
    if let Ok(canonical) = std::fs::canonicalize(repository) {
        if !paths.contains(&canonical) {
            paths.push(canonical);
        }
    }
    paths
        .into_iter()
        .map(|path| directory.join(crate::startup::socket_name(&path)))
        .collect()
}

/// Connects to the running backend of the repository. Never starts one: a
/// backend without a TUI could not answer anyway.
pub fn connect_backend(options: &Options, runtime: &Path) -> Result<UnixStream, String> {
    if let Some(socket) = &options.backend_socket {
        return connect_verified(socket)
            .map_err(|error| format!("cannot connect to {}: {error}", socket.display()));
    }
    let candidates = backend_candidates(runtime, &options.repository);
    for socket in &candidates {
        if let Ok(stream) = connect_verified(socket) {
            return Ok(stream);
        }
    }
    Err(format!(
        "no nix-secrets backend runs for {}; open the nix-secrets TUI and retry \
         (or pass --local to decrypt here)",
        options.repository.display()
    ))
}

/// An open, approved session on the backend. Dropping it without
/// [`BackendSession::end`] also ends it: the backend sees the disconnect.
pub struct BackendSession {
    stream: UnixStream,
    pub socket: PathBuf,
}

/// Asks the TUI behind `stream` for `identifiers`; blocks until the
/// operator answers.
pub fn request(mut stream: UnixStream, identifiers: &[String]) -> Result<BackendSession, String> {
    let io = |error: io::Error| format!("backend connection failed: {error}");
    write_json(
        &mut stream,
        &Request::RequestSecrets {
            identifiers: identifiers.to_vec(),
        },
    )
    .map_err(io)?;
    match read_json::<Response>(&mut stream).map_err(io)? {
        Some(Response::SecretSession { socket }) => Ok(BackendSession { stream, socket }),
        Some(Response::Error { message }) => Err(message),
        Some(other) => Err(format!("unexpected backend response: {other:?}")),
        None => Err("the backend closed the connection".into()),
    }
}

impl BackendSession {
    /// Ends the session and waits until the backend has removed the socket
    /// and erased the values.
    pub fn end(mut self) -> Result<(), String> {
        write_json(&mut self.stream, &Request::EndSecretSession)
            .map_err(|error| error.to_string())?;
        match read_json::<Response>(&mut self.stream) {
            Ok(Some(Response::SecretSessionEnded)) => Ok(()),
            Ok(other) => Err(format!("unexpected backend response: {other:?}")),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_identifiers_and_command() {
        let parsed = parse(
            os(&[
                "--repository",
                "/repo",
                "a.b.c.d",
                "a.b.c.e",
                "--",
                "sign",
                "--key-command",
            ]),
            "/cwd".into(),
        )
        .unwrap();
        assert_eq!(parsed.options.repository, PathBuf::from("/repo"));
        assert!(!parsed.options.local);
        assert_eq!(parsed.identifiers, ["a.b.c.d", "a.b.c.e"]);
        assert_eq!(parsed.command, os(&["sign", "--key-command"]));
        assert!(parse(os(&["a.b.c.d"]), "/".into()).is_err(), "no command");
        assert!(
            parse(os(&["--", "true"]), "/".into()).is_err(),
            "no identifier"
        );
        assert!(parse(os(&["a.b.c.d", "--"]), "/".into()).is_err());
        assert!(parse(os(&["a.b.c.d", "a.b.c.d", "--", "x"]), "/".into()).is_err());
        assert!(parse(os(&["a.b.c.d", "--local", "--", "x"]), "/".into()).is_err());
    }

    #[test]
    fn local_only_options_require_local() {
        let error = parse(
            os(&["--secret-identity", "/k", "a.b.c.d", "--", "x"]),
            "/".into(),
        )
        .unwrap_err();
        assert!(error.contains("--local"), "{error}");
        let local = parse(
            os(&["--local", "--secret-identity", "/k", "a.b.c.d", "--", "x"]),
            "/".into(),
        )
        .unwrap();
        assert!(local.options.local);
        assert_eq!(local.options.identity, Some(PathBuf::from("/k")));
    }
}
