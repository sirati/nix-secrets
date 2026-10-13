//! Run a command with a private agent exposing exactly one public key.
//!
//! The operator approves the SSH logins before anything connects: before
//! COMMAND starts, or with `--approve-on-request` when COMMAND runs
//! `nix-secrets approve-ssh-login`. A signer the TUI detached for that
//! approval then signs each login without asking anyone, so no login waits
//! for a person while the server counts its LoginGraceTime. A login without
//! a live approval is refused, never asked for.
use crate::with_secrets::{connect_backend, Options};
use nix_secrets_core::framing::write_json;
use nix_secrets_core::git::agent::{read_message, write_message, AgentProxy, FAILURE};
use nix_secrets_core::ssh_auth::{identities, key_blob, put_string, LoginGrantRequest, SignatureRequest};
use nix_secrets_core::{Request, Response};
use std::ffi::OsString;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const USAGE: &str = "usage: nix-secrets with-ssh-agent --public-key FILE --destination USER@HOST [--reason TEXT] [--approve-on-request] [--repository PATH] [--backend-socket PATH] -- COMMAND [ARG ...]";
pub const APPROVE_USAGE: &str = "usage: nix-secrets approve-ssh-login";

/// The agent extension `approve-ssh-login` sends to the private agent.
const APPROVE_EXTENSION: &[u8] = b"approve-login@nix-secrets.sirati.me";
const EXTENSION: u8 = 27;
const SUCCESS: u8 = 6;
/// An approval with less left than this is renewed before a connection.
const RENEW_BEFORE: Duration = Duration::from_secs(120);

#[derive(Clone, Debug)]
pub struct Invocation {
    pub options: Options,
    pub public_key: String,
    pub destination: String,
    /// COMMAND asks for the approval itself, before it connects.
    pub on_request: bool,
    pub command: Vec<OsString>,
}

pub fn parse(arguments: Vec<OsString>, cwd: PathBuf) -> Result<Invocation, String> {
    let mut options = Options {
        repository: cwd,
        ..Options::default()
    };
    let mut public_key = None;
    let mut destination = None;
    let mut on_request = false;
    let mut arguments = arguments.into_iter();
    let command;
    loop {
        let arg = arguments.next().ok_or(USAGE)?;
        if arg == "--" {
            command = arguments.collect::<Vec<_>>();
            break;
        }
        if arg == "--approve-on-request" {
            on_request = true;
            continue;
        }
        let value = arguments.next().ok_or(USAGE)?;
        match arg.to_str() {
            Some("--public-key") => {
                public_key = Some(
                    std::fs::read_to_string(&value)
                        .map_err(|e| format!("cannot read public key: {e}"))?,
                )
            }
            Some("--destination") => {
                destination = Some(value.into_string().map_err(|_| "invalid destination")?)
            }
            Some("--reason") => {
                options.reason = Some(value.into_string().map_err(|_| "invalid reason")?)
            }
            Some("--repository") => options.repository = value.into(),
            Some("--backend-socket") => options.backend_socket = Some(value.into()),
            _ => return Err(USAGE.into()),
        }
    }
    if command.is_empty() {
        return Err(USAGE.into());
    }
    let public_key = public_key.ok_or(USAGE)?.trim().to_owned();
    key_blob(&public_key)?;
    let destination = destination.ok_or(USAGE)?;
    LoginGrantRequest {
        public_key: public_key.clone(),
        destination: destination.clone(),
    }
    .validate()?;
    if options
        .reason
        .as_ref()
        .is_some_and(|r| r.len() > nix_secrets_core::secret_request::MAX_REQUEST_REASON_BYTES)
    {
        return Err("reason exceeds 4096 bytes".into());
    }
    Ok(Invocation {
        options,
        public_key,
        destination,
        on_request,
        command,
    })
}

/// A live approval of the logins.
struct Grant {
    id: String,
    expires: Instant,
    remaining: u32,
}

/// The backend connection and the approval it holds. The backend binds the
/// approval to this connection.
struct Session {
    backend: UnixStream,
    login: LoginGrantRequest,
    reason: Option<String>,
    procedure: Option<String>,
    grant: Option<Grant>,
}

impl Session {
    /// Asks the operator to approve the logins, unless the current approval
    /// has enough left. Waits as long as the operator takes: nothing has
    /// connected yet.
    fn approve(&mut self) -> Result<(), String> {
        let now = Instant::now();
        if self
            .grant
            .as_ref()
            .is_some_and(|grant| grant.remaining > 0 && grant.expires > now + RENEW_BEFORE)
        {
            return Ok(());
        }
        self.grant = None;
        let io = |error: io::Error| format!("backend connection failed: {error}");
        write_json(
            &mut self.backend,
            &Request::RequestSshLoginGrant {
                request: self.login.clone(),
                reason: self.reason.clone(),
                procedure: self.procedure.clone(),
                progress: true,
            },
        )
        .map_err(io)?;
        match crate::with_secrets::read_answer(&mut self.backend).map_err(io)? {
            Some(Response::SshLoginGranted {
                grant,
                expires_in_seconds,
                signatures,
            }) => {
                self.grant = Some(Grant {
                    id: grant,
                    expires: now + Duration::from_secs(expires_in_seconds),
                    remaining: signatures,
                });
                Ok(())
            }
            Some(Response::Error { message }) => Err(message),
            _ => Err("backend did not answer the SSH login approval".into()),
        }
    }

    /// Signs one login under the live approval, without asking anyone.
    fn sign(&mut self, request: SignatureRequest) -> Result<Vec<u8>, String> {
        let grant = self
            .grant
            .as_mut()
            .filter(|grant| grant.remaining > 0 && grant.expires > Instant::now())
            .ok_or(
                "no SSH login approval is live; approve the logins before connecting \
                 (nix-secrets approve-ssh-login)",
            )?;
        grant.remaining -= 1;
        let grant = grant.id.clone();
        let io = |error: io::Error| format!("backend connection failed: {error}");
        write_json(
            &mut self.backend,
            &Request::RequestSshSignature {
                request,
                reason: self.reason.clone(),
                procedure: None,
                progress: true,
                grant: Some(grant),
            },
        )
        .map_err(io)?;
        match crate::with_secrets::read_answer(&mut self.backend).map_err(io)? {
            Some(Response::SshSignature { reply }) => {
                nix_secrets_core::ssh_auth::validate_reply(&reply)?;
                Ok(reply)
            }
            Some(Response::Error { message }) => {
                // The TUI ended this approval; the next connection asks anew.
                self.grant = None;
                Err(message)
            }
            _ => Err("backend did not return an SSH signature".into()),
        }
    }
}

/// Whether `message` is the approval extension.
fn is_approval(message: &[u8]) -> bool {
    let mut expected = vec![EXTENSION];
    put_string(&mut expected, APPROVE_EXTENSION);
    message == expected
}

pub fn run(invocation: Invocation, runtime: &Path) -> Result<std::process::ExitStatus, String> {
    // Connect before starting the child, so an absent TUI/backend fails early.
    let backend = connect_backend(&invocation.options, runtime)?;
    let proxy = AgentProxy::bind(&nix_secrets_core::private_socket::runtime_directory())
        .map_err(|e| e.to_string())?
        .with_owner(std::process::id());
    let socket = proxy.path().to_owned();
    let key = invocation.public_key.clone();
    let destination = invocation.destination.clone();
    let mut session = Session {
        backend,
        login: LoginGrantRequest {
            public_key: invocation.public_key,
            destination: invocation.destination,
        },
        reason: invocation.options.reason,
        procedure: crate::with_secrets::procedure_token(),
        grant: None,
    };
    if !invocation.on_request {
        // COMMAND starts only once the logins are approved.
        session.approve()?;
    }
    let (done, finished) = mpsc::channel();
    let serving = std::thread::spawn(move || {
        let request = |message: &[u8]| SignatureRequest {
            public_key: key.clone(),
            destination: destination.clone(),
            message: message.to_vec(),
        };
        proxy.serve_until_filtered(
            &finished,
            |message| message == [11] || is_approval(message) || request(message).validate().is_ok(),
            |message| {
                if message == [11] {
                    return identities(&key).map_err(io::Error::other);
                }
                let result = if is_approval(message) {
                    session.approve().map(|()| vec![SUCCESS])
                } else {
                    session.sign(request(message))
                };
                Ok(result.unwrap_or_else(|error| {
                    eprintln!("nix-secrets: SSH authentication failed: {error}");
                    FAILURE[4..].to_vec()
                }))
            },
        )
    });
    let (program, arguments) = invocation.command.split_first().unwrap();
    let status = std::process::Command::new(program)
        .args(arguments)
        .env("SSH_AUTH_SOCK", &socket)
        .env("NIX_SECRETS_SSH_AGENT", &socket)
        .status()
        .map_err(|e| e.to_string());
    let _ = done.send(());
    serving
        .join()
        .map_err(|_| "SSH authentication proxy stopped unexpectedly")?
        .map_err(|e| e.to_string())?;
    status
}

/// `nix-secrets approve-ssh-login`: run under `with-ssh-agent
/// --approve-on-request`, it returns once the operator approved the logins
/// (or an earlier approval still has enough left). Connect only after it
/// succeeded.
pub fn approve(arguments: Vec<OsString>) -> Result<(), String> {
    if !arguments.is_empty() {
        return Err(APPROVE_USAGE.into());
    }
    let socket = std::env::var_os("NIX_SECRETS_SSH_AGENT")
        .ok_or("approve-ssh-login runs only under nix-secrets with-ssh-agent")?;
    let mut agent = UnixStream::connect(&socket)
        .map_err(|error| format!("cannot reach the nix-secrets SSH agent: {error}"))?;
    let mut message = vec![EXTENSION];
    put_string(&mut message, APPROVE_EXTENSION);
    write_message(&mut agent, &message).map_err(|error| error.to_string())?;
    match read_message(&mut agent).map_err(|error| error.to_string())? {
        Some(reply) if reply == [SUCCESS] => Ok(()),
        _ => Err("the SSH logins were not approved".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_on_request_is_a_flag_and_the_destination_is_checked() {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("key.pub");
        std::fs::write(
            &key,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBYnTKFSbXNz3YcBHeHMJT+t2d+gc/eUEe3idGUu7O3v test\n",
        )
        .unwrap();
        let parse = |extra: &[&str]| {
            let mut arguments: Vec<OsString> = vec!["--public-key".into(), key.clone().into()];
            arguments.extend(extra.iter().map(OsString::from));
            arguments.extend(["--".into(), "true".into()]);
            parse(arguments, directory.path().to_owned())
        };
        let eager = parse(&["--destination", "update@ns1"]).unwrap();
        assert!(!eager.on_request);
        let lazy = parse(&["--approve-on-request", "--destination", "update@ns1"]).unwrap();
        assert!(lazy.on_request);
        assert_eq!(lazy.command, [OsString::from("true")]);
        assert!(parse(&["--destination", "ns1"]).is_err());
        assert!(parse(&["--destination", "up date@ns1"]).is_err());
    }

    #[test]
    fn only_the_exact_extension_asks_for_approval() {
        let mut message = vec![EXTENSION];
        put_string(&mut message, APPROVE_EXTENSION);
        assert!(is_approval(&message));
        message.push(0);
        assert!(!is_approval(&message));
        let mut other = vec![EXTENSION];
        put_string(&mut other, b"session-bind@openssh.com");
        assert!(!is_approval(&other));
    }
}
