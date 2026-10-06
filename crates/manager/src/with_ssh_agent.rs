//! Run a command with a private agent exposing exactly one public key.
//! Every SSH authentication signature is approved and produced by the TUI.
use crate::with_secrets::{connect_backend, Options};
use nix_secrets_core::framing::write_json;
use nix_secrets_core::git::agent::{AgentProxy, FAILURE};
use nix_secrets_core::ssh_auth::{identities, key_blob, SignatureRequest};
use nix_secrets_core::{Request, Response};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

pub const USAGE: &str = "usage: nix-secrets with-ssh-agent --public-key FILE --destination USER@HOST [--reason TEXT] [--repository PATH] [--backend-socket PATH] -- COMMAND [ARG ...]";

#[derive(Clone, Debug)]
pub struct Invocation {
    pub options: Options,
    pub public_key: String,
    pub destination: String,
    pub command: Vec<OsString>,
}

pub fn parse(arguments: Vec<OsString>, cwd: PathBuf) -> Result<Invocation, String> {
    let mut options = Options {
        repository: cwd,
        ..Options::default()
    };
    let mut public_key = None;
    let mut destination = None;
    let mut arguments = arguments.into_iter();
    let command;
    loop {
        let arg = arguments.next().ok_or(USAGE)?;
        if arg == "--" {
            command = arguments.collect::<Vec<_>>();
            break;
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
    if !destination.contains('@') {
        return Err("destination must be user@host".into());
    }
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
        command,
    })
}

pub fn run(invocation: Invocation, runtime: &Path) -> Result<std::process::ExitStatus, String> {
    // Connect before starting the child, so an absent TUI/backend fails early.
    let mut backend = connect_backend(&invocation.options, runtime)?;
    let proxy = AgentProxy::bind(&nix_secrets_core::private_socket::runtime_directory())
        .map_err(|e| e.to_string())?;
    let socket = proxy.path().to_owned();
    let key = invocation.public_key;
    let destination = invocation.destination;
    let reason = invocation.options.reason;
    let procedure = crate::with_secrets::procedure_token();
    let (done, finished) = mpsc::channel();
    let serving = std::thread::spawn(move || {
        let request = |message: &[u8]| SignatureRequest {
            public_key: key.clone(),
            destination: destination.clone(),
            message: message.to_vec(),
        };
        proxy.serve_until_filtered(
            &finished,
            |message| message == [11] || request(message).validate().is_ok(),
            |message| {
                if message == [11] {
                    return identities(&key).map_err(io::Error::other);
                }
                let result = (|| {
                    write_json(
                        &mut backend,
                        &Request::RequestSshSignature {
                            request: request(message),
                            reason: reason.clone(),
                            procedure: procedure.clone(),
                            progress: true,
                        },
                    )?;
                    match crate::with_secrets::read_answer(&mut backend)? {
                        Some(Response::SshSignature { reply }) => {
                            nix_secrets_core::ssh_auth::validate_reply(&reply)
                                .map_err(io::Error::other)?;
                            Ok(reply)
                        }
                        Some(Response::Error { message }) => Err(io::Error::other(message)),
                        _ => Err(io::Error::other("backend did not return an SSH signature")),
                    }
                })();
                match result {
                    Ok(reply) => Ok(reply),
                    Err(error) => {
                        eprintln!("nix-secrets: SSH authentication failed: {error}");
                        Ok(FAILURE[4..].to_vec())
                    }
                }
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
