//! Which key the deployment SSH offers.
//!
//! OpenSSH offers every agent key in turn, and sshd drops the connection after
//! MaxAuthTries (6 by default) failures. An agent holding many keys, such as
//! a password manager's, is therefore cut off before it reaches the one key
//! the target's forwarder account authorizes. The deployment offers only the
//! keys the schema names for the host (`deployment.identityPublicKeys`): a
//! private key file the client's ssh config names whose `.pub` matches, or
//! else the agent's copy, by passing its public half with IdentitiesOnly.
use crate::fingerprint;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What ssh is told to offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Offer {
    /// A private key file from the client's configuration.
    File(PathBuf),
    /// A key held by the agent: `algorithm base64 comment`.
    Agent(String),
}

impl Offer {
    /// How the key is named to the operator: the agent's comment (the name
    /// 1Password shows) or the file, with a short fingerprint.
    pub fn describe(&self) -> String {
        match self {
            Self::File(path) => format!("the key file {}", path.display()),
            Self::Agent(line) => describe_line(line),
        }
    }
}

/// `"IT Secrets" (ssh-ed25519 SHA256:…)`, or the fingerprint alone.
pub fn describe_line(line: &str) -> String {
    let mut fields = line.split_whitespace();
    let algorithm = fields.next().unwrap_or("");
    let encoded = fields.next().unwrap_or("");
    let comment = fields.collect::<Vec<_>>().join(" ");
    let print = format!("{algorithm} {}", fingerprint(encoded));
    if comment.is_empty() {
        print
    } else {
        format!("\"{comment}\" ({print})")
    }
}

/// `algorithm base64` of an OpenSSH public key line.
fn key_of(line: &str) -> Option<(String, String)> {
    let mut fields = line.split_whitespace();
    let algorithm = fields.next()?;
    let encoded = fields.next()?;
    Some((algorithm.to_owned(), encoded.to_owned()))
}

/// `ssh -G` for the destination: the identity files and agent ssh would use.
#[derive(Clone, Debug, Default)]
pub struct ClientConfig {
    pub identity_files: Vec<PathBuf>,
    /// `None`: the agent from `SSH_AUTH_SOCK`; `Some("none")` disables it.
    pub identity_agent: Option<String>,
}

pub fn client_config(program: &OsString, destination: &OsString, port: u16) -> ClientConfig {
    let output = Command::new(program)
        .args(["-G", "-p", &port.to_string(), "--"])
        .arg(destination)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let text = output
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    parse_client_config(&text, std::env::var_os("HOME").map(PathBuf::from))
}

pub(crate) fn parse_client_config(text: &str, home: Option<PathBuf>) -> ClientConfig {
    let expand = |value: &str| -> String {
        match (value.strip_prefix("~/"), &home) {
            (Some(rest), Some(home)) => home.join(rest).display().to_string(),
            _ => value.to_owned(),
        }
    };
    let mut config = ClientConfig::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key {
            "identityfile" => config.identity_files.push(PathBuf::from(expand(value))),
            "identityagent" if value != "SSH_AUTH_SOCK" => {
                let value = value
                    .strip_prefix('$')
                    .and_then(std::env::var_os)
                    .map(|value| value.to_string_lossy().into_owned())
                    .unwrap_or_else(|| expand(value));
                config.identity_agent = Some(value);
            }
            _ => {}
        }
    }
    config
}

/// The public key lines the agent holds, with their comments, or why it
/// cannot say. Listing keys never asks 1Password for approval.
pub fn agent_keys(agent: Option<&str>) -> Result<Vec<String>, String> {
    let mut command = Command::new("ssh-add");
    command.arg("-L").stdin(Stdio::null()).stderr(Stdio::null());
    match agent {
        Some("none") => return Err("ssh's IdentityAgent is none".into()),
        Some(socket) => {
            command.env("SSH_AUTH_SOCK", socket);
        }
        None if std::env::var_os("SSH_AUTH_SOCK").is_none_or(|value| value.is_empty()) => {
            return Err("no ssh-agent is configured (SSH_AUTH_SOCK is unset)".into());
        }
        None => {}
    }
    let output = command
        .output()
        .map_err(|error| format!("cannot run ssh-add: {error}"))?;
    // ssh-add -L exits 1 for an agent without keys.
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(' '))
        .map(str::to_owned)
        .collect())
}

/// Chooses what to offer for `wanted` (public key lines), or explains why no
/// wanted key is available.
pub fn choose(
    wanted: &[String],
    config: &ClientConfig,
    agent: Result<Vec<String>, String>,
    read_public: &dyn Fn(&Path) -> Option<String>,
) -> Result<Vec<Offer>, String> {
    let wanted_keys = wanted
        .iter()
        .filter_map(|line| key_of(line))
        .collect::<Vec<_>>();
    let mut offers = Vec::new();
    for file in &config.identity_files {
        let mut public = file.as_os_str().to_owned();
        public.push(".pub");
        if let Some(line) = read_public(Path::new(&public)) {
            if key_of(&line).is_some_and(|key| wanted_keys.contains(&key)) {
                offers.push(Offer::File(file.clone()));
            }
        }
    }
    let agent_error = match &agent {
        Ok(lines) => {
            for line in lines {
                if key_of(line).is_some_and(|key| wanted_keys.contains(&key)) {
                    offers.push(Offer::Agent(line.clone()));
                }
            }
            None
        }
        Err(error) => Some(error.clone()),
    };
    if !offers.is_empty() {
        return Ok(offers);
    }
    let names = wanted
        .iter()
        .map(|line| describe_line(line))
        .collect::<Vec<_>>()
        .join(", ");
    let agent = match (&config.identity_agent, agent_error) {
        (_, Some(error)) => format!("the ssh-agent could not be asked: {error}"),
        (Some(socket), None) => format!("it is not in your ssh-agent ({socket})"),
        (None, None) => "it is not in your ssh-agent (SSH_AUTH_SOCK)".to_owned(),
    };
    Err(format!(
        "the forwarder key {names} is not available: {agent}, and no IdentityFile of this machine's ssh config holds it. Add it to your ssh-agent (in 1Password, allow the key for the SSH agent) and retry."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RIGHT: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f forwarder";
    const OTHER: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA other";

    fn config(files: &[&str]) -> ClientConfig {
        ClientConfig {
            identity_files: files.iter().map(PathBuf::from).collect(),
            identity_agent: Some("/agent.sock".into()),
        }
    }

    #[test]
    fn offers_only_the_wanted_agent_key_among_many() {
        let named = RIGHT.replace(" forwarder", " IT Secrets");
        let mut agent = (0..12).map(|_| OTHER.to_owned()).collect::<Vec<_>>();
        agent.insert(7, named.clone());
        let offers = choose(&[RIGHT.into()], &config(&[]), Ok(agent), &|_| None).unwrap();
        assert_eq!(offers, [Offer::Agent(named)]);
        assert!(
            offers[0].describe().starts_with("\"IT Secrets\" (ssh-ed25519 SHA256:"),
            "{}",
            offers[0].describe()
        );
    }

    #[test]
    fn prefers_a_configured_key_file_holding_the_key() {
        let offers = choose(
            &[RIGHT.into()],
            &config(&["/home/op/.ssh/id_rsa", "/home/op/.ssh/id_ed25519"]),
            Err("no agent".into()),
            &|path| (path == Path::new("/home/op/.ssh/id_ed25519.pub")).then(|| RIGHT.to_owned()),
        )
        .unwrap();
        assert_eq!(offers, [Offer::File("/home/op/.ssh/id_ed25519".into())]);
    }

    #[test]
    fn a_missing_key_is_named_with_its_fingerprint_and_the_agent() {
        let error = choose(
            &[RIGHT.into()],
            &config(&[]),
            Ok(vec![OTHER.into()]),
            &|_| None,
        )
        .unwrap_err();
        assert!(
            error.contains("the forwarder key \"forwarder\" (ssh-ed25519 SHA256:"),
            "{error}"
        );
        assert!(error.contains("not in your ssh-agent (/agent.sock)"), "{error}");
    }

    #[test]
    fn reads_the_identity_files_and_agent_ssh_would_use() {
        let config = parse_client_config(
            "user x\nidentityagent ~/.1password/agent.sock\nidentityfile ~/.ssh/id_ed25519\nidentitiesonly no\n",
            Some("/home/op".into()),
        );
        assert_eq!(
            config.identity_files,
            [PathBuf::from("/home/op/.ssh/id_ed25519")]
        );
        assert_eq!(
            config.identity_agent.as_deref(),
            Some("/home/op/.1password/agent.sock")
        );
        let default = parse_client_config("identityagent SSH_AUTH_SOCK\n", None);
        assert_eq!(default.identity_agent, None);
    }
}
