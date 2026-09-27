//! `nix-secrets deploy HOST`: asks the attached TUI to deploy a host.
//!
//! ```text
//! nix-secrets deploy [--repository PATH] [--backend-socket PATH] [--wait] [--allow-partial] HOST
//! ```
//!
//! The backend of the repository builds an approval request covering every
//! deployable value of `HOST` and queues it for the registered TUIs, which
//! show it like any deployment request: host-key check, the list of values
//! to create, replace, generate and derive, the missing-values refusal, then
//! the deployment. Without `--wait` the command exits once the request is
//! queued; with it, it waits for the operator and prints the result.
use crate::client::BackendClient;
use crate::with_secrets::{connect_backend, Options};
use nix_secrets_core::{ApprovalStatus, Decision};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const USAGE: &str = "usage: nix-secrets deploy [--repository PATH] [--backend-socket PATH] \
[--wait] [--allow-partial] HOST";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub options: Options,
    pub host: String,
    pub wait: bool,
    pub allow_partial: bool,
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
    let mut host = None;
    let mut wait = false;
    let mut allow_partial = false;
    while let Some(argument) = arguments.next() {
        let text = argument
            .to_str()
            .ok_or_else(|| format!("unexpected argument {argument:?}; {USAGE}"))?
            .to_owned();
        let mut path = |name: &str| {
            arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| format!("{name} requires a path"))
        };
        match text.as_str() {
            "--repository" => options.repository = path("--repository")?,
            "--backend-socket" => options.backend_socket = Some(path("--backend-socket")?),
            "--wait" => wait = true,
            // Kept as an alias: missing values never block a deployment.
            "--allow-partial" => allow_partial = true,
            _ if text.starts_with('-') => return Err(format!("unexpected argument {text:?}; {USAGE}")),
            _ if host.is_some() => return Err(format!("name exactly one host; {USAGE}")),
            _ => host = Some(text),
        }
    }
    Ok(Invocation {
        options,
        host: host.ok_or_else(|| format!("name the host to deploy; {USAGE}"))?,
        wait,
        allow_partial,
    })
}

/// What happened to a deployment request, for the exit status.
#[derive(Debug, Eq, PartialEq)]
pub enum Outcome {
    Queued,
    Deployed(String),
    Rejected(String),
    Cancelled,
}

/// Queues the request and, with `--wait`, follows it until the operator
/// resolves it. `progress` receives one line per state change.
pub fn run(
    invocation: &Invocation,
    runtime: &Path,
    poll: Duration,
    progress: &mut impl FnMut(&str),
) -> Result<Outcome, String> {
    let stream = connect_backend(&invocation.options, runtime)
        .map_err(|error| error.replace(" (or pass --local to decrypt here)", ""))?;
    let mut client = BackendClient::new(stream);
    let request = client
        .request_deployment(&invocation.host, invocation.allow_partial)
        .map_err(|error| error.to_string())?;
    progress(&format!(
        "requested a deployment of {} ({} values), request {}; approve it in the nix-secrets TUI",
        request.target,
        request.secrets.len(),
        request.id
    ));
    if !invocation.wait {
        return Ok(Outcome::Queued);
    }
    let mut claimed = false;
    loop {
        match client
            .approval_status(&request.id)
            .map_err(|error| error.to_string())?
        {
            ApprovalStatus::Pending => claimed = false,
            ApprovalStatus::Claimed { .. } => {
                if !claimed {
                    progress("the TUI opened the request; waiting for the operator");
                }
                claimed = true;
            }
            ApprovalStatus::Resolved {
                decision: Decision::Approved,
                message,
            } => return Ok(Outcome::Deployed(message.unwrap_or_else(|| "deployed".into()))),
            ApprovalStatus::Resolved {
                decision: Decision::Rejected,
                message,
            } => {
                return Ok(Outcome::Rejected(
                    message.unwrap_or_else(|| "rejected".into()),
                ))
            }
            ApprovalStatus::Cancelled => return Ok(Outcome::Cancelled),
        }
        std::thread::sleep(poll);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_host_and_options() {
        let parsed = parse(
            os(&["--repository", "/repo", "--wait", "--allow-partial", "ns1"]),
            "/cwd".into(),
        )
        .unwrap();
        assert_eq!(parsed.options.repository, PathBuf::from("/repo"));
        assert_eq!(parsed.host, "ns1");
        assert!(parsed.wait && parsed.allow_partial);
        let plain = parse(os(&["ns1"]), "/cwd".into()).unwrap();
        assert_eq!(plain.options.repository, PathBuf::from("/cwd"));
        assert!(!plain.wait && !plain.allow_partial);
        assert!(parse(os(&[]), "/".into()).is_err());
        assert!(parse(os(&["a", "b"]), "/".into()).is_err());
        assert!(parse(os(&["--local", "a"]), "/".into()).is_err());
        assert!(parse(os(&["--backend-socket"]), "/".into()).is_err());
    }
}
