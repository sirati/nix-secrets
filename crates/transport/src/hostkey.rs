use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const MAX_TOOL_OUTPUT: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentedKey {
    pub algorithm: String,
    pub encoded: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostIdentity {
    pub host: String,
    pub port: u16,
    pub keys: Vec<PresentedKey>,
    pub other_names_with_keys: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Accept,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKeyStatus {
    Known,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct HostKeyPreflight {
    pub identity: HostIdentity,
    pub status: HostKeyStatus,
    pub(crate) known_host_lines: Vec<String>,
}

pub trait HostKeyDecision {
    fn accept_unknown(&mut self, identity: &HostIdentity) -> Decision;
}

impl<F> HostKeyDecision for F
where
    F: FnMut(&HostIdentity) -> Decision,
{
    fn accept_unknown(&mut self, identity: &HostIdentity) -> Decision {
        self(identity)
    }
}

#[derive(Debug)]
pub enum HostKeyError {
    Io(io::Error),
    Tool(String),
    NoKeys,
    Changed,
    UnknownRejected,
}

impl fmt::Display for HostKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Tool(message) => f.write_str(message),
            Self::NoKeys => f.write_str("target did not present an SSH host key"),
            Self::Changed => f.write_str("SSH host key changed"),
            Self::UnknownRejected => f.write_str("unknown SSH host was rejected"),
        }
    }
}
impl std::error::Error for HostKeyError {}
impl From<io::Error> for HostKeyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub struct HostKeyVerifier {
    known_hosts: Vec<PathBuf>,
    ssh_keyscan: OsString,
    ssh_keygen: OsString,
}

impl HostKeyVerifier {
    pub fn new(known_hosts: Vec<PathBuf>) -> Self {
        Self {
            known_hosts,
            ssh_keyscan: "ssh-keyscan".into(),
            ssh_keygen: "ssh-keygen".into(),
        }
    }

    pub(crate) fn verify(
        &self,
        host: &str,
        port: u16,
        decision: &mut impl HostKeyDecision,
    ) -> Result<VerifiedHost, HostKeyError> {
        self.verify_with(host, port, decision, &ProcessRunner)
    }

    pub fn preflight(&self, host: &str, port: u16) -> Result<HostKeyPreflight, HostKeyError> {
        self.preflight_with(host, port, &ProcessRunner)
    }

    fn verify_with(
        &self,
        host: &str,
        port: u16,
        decision: &mut impl HostKeyDecision,
        runner: &impl Runner,
    ) -> Result<VerifiedHost, HostKeyError> {
        let preflight = self.preflight_with(host, port, runner)?;
        if preflight.status == HostKeyStatus::Unknown
            && decision.accept_unknown(&preflight.identity) == Decision::Reject
        {
            return Err(HostKeyError::UnknownRejected);
        }
        Ok(VerifiedHost {
            known_host_lines: preflight.known_host_lines,
        })
    }

    fn preflight_with(
        &self,
        host: &str,
        port: u16,
        runner: &impl Runner,
    ) -> Result<HostKeyPreflight, HostKeyError> {
        let scan = runner.run(
            &self.ssh_keyscan,
            &[
                "-T".into(),
                "10".into(),
                "-p".into(),
                port.to_string().into(),
                "--".into(),
                host.into(),
            ],
        )?;
        if !scan.success {
            return Err(HostKeyError::Tool("ssh-keyscan failed".into()));
        }
        let scanned = parse_key_lines(&scan.stdout);
        if scanned.is_empty() {
            return Err(HostKeyError::NoKeys);
        }
        let lookup = lookup_name(host, port);
        let mut known = Vec::new();
        for path in &self.known_hosts {
            if !path.exists() {
                continue;
            }
            let output = runner.run(
                &self.ssh_keygen,
                &[
                    "-F".into(),
                    lookup.clone().into(),
                    "-f".into(),
                    path.as_os_str().into(),
                ],
            )?;
            if output.success {
                known.extend(parse_key_lines(&output.stdout));
            }
        }
        let matching: Vec<KeyLine> = scanned
            .iter()
            .filter(|candidate| known.iter().any(|entry| entry.same_key(candidate)))
            .cloned()
            .collect();
        if !known.is_empty() && matching.is_empty() {
            return Err(HostKeyError::Changed);
        }
        let (accepted, status) = if known.is_empty() {
            (scanned, HostKeyStatus::Unknown)
        } else {
            (matching, HostKeyStatus::Known)
        };
        let identity = HostIdentity {
            host: host.into(),
            port,
            keys: accepted.iter().map(KeyLine::presented).collect(),
            other_names_with_keys: aliases(&self.known_hosts, &accepted)?,
        };
        Ok(HostKeyPreflight {
            identity,
            status,
            known_host_lines: accepted
                .into_iter()
                .map(|key| key.for_host(&lookup))
                .collect(),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedHost {
    pub(crate) known_host_lines: Vec<String>,
}

#[derive(Clone, Debug)]
struct KeyLine {
    hosts: String,
    algorithm: String,
    encoded: String,
}

impl KeyLine {
    fn same_key(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.encoded == other.encoded
    }
    fn presented(&self) -> PresentedKey {
        PresentedKey {
            algorithm: self.algorithm.clone(),
            encoded: self.encoded.clone(),
        }
    }
    fn for_host(self, host: &str) -> String {
        format!("{host} {} {}", self.algorithm, self.encoded)
    }
}

fn parse_key_lines(bytes: &[u8]) -> Vec<KeyLine> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let hosts = fields.next()?;
            if hosts.starts_with('@') {
                return None;
            }
            Some(KeyLine {
                hosts: hosts.into(),
                algorithm: fields.next()?.into(),
                encoded: fields.next()?.into(),
            })
        })
        .collect()
}

fn aliases(paths: &[PathBuf], keys: &[KeyLine]) -> Result<Vec<String>, HostKeyError> {
    let mut names = BTreeSet::new();
    for path in paths {
        let contents = match fs::read(path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for line in parse_key_lines(&contents) {
            if keys.iter().any(|key| key.same_key(&line)) {
                for name in line.hosts.split(',').filter(|name| !name.starts_with('|')) {
                    names.insert(name.to_owned());
                }
            }
        }
    }
    Ok(names.into_iter().collect())
}

fn lookup_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.into()
    } else {
        format!("[{host}]:{port}")
    }
}

mod runner;
#[cfg(test)]
use runner::Output;
use runner::{ProcessRunner, Runner};

#[cfg(test)]
mod tests;
