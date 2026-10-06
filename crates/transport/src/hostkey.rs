use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const MAX_TOOL_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_DISCOVERY_ATTEMPTS: usize = 6;
const DISCOVERY_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
const DISCOVERY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentedKey {
    pub algorithm: String,
    pub encoded: String,
}

impl PresentedKey {
    /// The OpenSSH fingerprint, `SHA256:` and unpadded base64, as
    /// `ssh-keygen -l` prints it.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.encoded)
    }

    /// `ssh-ed25519 SHA256:…`.
    pub fn describe(&self) -> String {
        format!("{} {}", self.algorithm, self.fingerprint())
    }
}

/// The OpenSSH SHA256 fingerprint of a base64 key blob.
pub fn fingerprint(encoded: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(blob) => format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(blob))
        ),
        Err(_) => format!("(undecodable key {encoded})"),
    }
}

/// A key recorded in a known_hosts file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownKey {
    pub file: PathBuf,
    pub line: Option<usize>,
    pub key: PresentedKey,
}

/// The host offered keys, none of which known_hosts records for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangedHostKey {
    pub host: String,
    pub port: u16,
    pub expected: Vec<KnownKey>,
    pub offered: Vec<PresentedKey>,
}

impl ChangedHostKey {
    /// The name `ssh-keygen -F/-R` uses: `host`, or `[host]:port`.
    pub fn lookup_name(&self) -> String {
        lookup_name(&self.host, self.port)
    }
}

impl fmt::Display for ChangedHostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lookup = self.lookup_name();
        let quoted = if self.port == 22 {
            lookup.clone()
        } else {
            format!("'{lookup}'")
        };
        writeln!(
            f,
            "SSH HOST KEY MISMATCH for {}:{}: the host offers keys that known_hosts does not record for it. Someone may be intercepting the connection, or the host was reinstalled.",
            self.host, self.port
        )?;
        for known in &self.expected {
            let line = known
                .line
                .map(|line| format!(" line {line}"))
                .unwrap_or_default();
            writeln!(
                f,
                "  expected: {} ({}{line})",
                known.key.describe(),
                known.file.display()
            )?;
        }
        for key in &self.offered {
            writeln!(f, "  offered:  {}", key.describe())?;
        }
        let mut files = self
            .expected
            .iter()
            .map(|known| known.file.clone())
            .collect::<Vec<_>>();
        files.dedup();
        let removals = files
            .iter()
            .map(|file| format!("`ssh-keygen -R {quoted} -f {}`", file.display()))
            .collect::<Vec<_>>()
            .join(" and ");
        write!(
            f,
            "First compare the offered fingerprints with the host's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on its console). If the host was reinstalled, remove the old key on this machine with {removals}, also for any IP address you reach it by, and retry the deployment."
        )
    }
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
    pub connection_warnings: Vec<String>,
    /// Where known_hosts records the accepted keys; empty for an unknown host.
    pub known: Vec<KnownKey>,
    pub(crate) known_host_lines: Vec<String>,
}

impl HostKeyPreflight {
    /// A scan result that known_hosts already trusts, without scanning;
    /// for tests of what happens before anything connects.
    pub fn known(identity: HostIdentity) -> Self {
        Self {
            identity,
            status: HostKeyStatus::Known,
            connection_warnings: Vec::new(),
            known: Vec::new(),
            known_host_lines: Vec::new(),
        }
    }
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
    Changed(Box<ChangedHostKey>),
    UnknownRejected,
}

impl fmt::Display for HostKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Tool(message) => f.write_str(message),
            Self::NoKeys => f.write_str("target did not present an SSH host key"),
            Self::Changed(changed) => changed.fmt(f),
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
    route: Option<std::sync::Arc<crate::BackendRoute>>,
}

impl HostKeyVerifier {
    pub fn with_route(mut self, route: Option<std::sync::Arc<crate::BackendRoute>>) -> Self {
        self.route = route;
        self
    }

    pub fn new(known_hosts: Vec<PathBuf>) -> Self {
        Self {
            known_hosts,
            ssh_keyscan: "ssh-keyscan".into(),
            ssh_keygen: "ssh-keygen".into(),
            route: None,
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

    /// Retry scans missing approved keys, accumulating exact approved subsets.
    /// A later scan may discover more keys,
    /// but only the previously approved keys are returned and pinned.
    pub fn preflight_approved(
        &self,
        host: &str,
        port: u16,
        approved: &HostIdentity,
    ) -> Result<HostKeyPreflight, HostKeyError> {
        self.preflight_approved_with(host, port, approved, &ProcessRunner)
    }

    fn preflight_approved_with(
        &self,
        host: &str,
        port: u16,
        approved: &HostIdentity,
        runner: &impl Runner,
    ) -> Result<HostKeyPreflight, HostKeyError> {
        if approved.host != host || approved.port != port {
            return Err(HostKeyError::Tool(
                "approved host-key target mismatch".into(),
            ));
        }
        if approved.keys.is_empty() {
            return Err(HostKeyError::NoKeys);
        }
        let mut observed = Vec::new();
        for attempt in 0..3 {
            let mut current =
                self.preflight_selected_with(host, port, runner, Some(&approved.keys))?;
            let complete_scan = approved
                .keys
                .iter()
                .all(|key| current.identity.keys.contains(key));
            // Extra keys are harmless only when this scan also contains the
            // entire approved set. A replacement alongside a partial set must
            // not be hidden by approved keys observed in an earlier scan.
            if !complete_scan
                && current
                    .identity
                    .keys
                    .iter()
                    .any(|key| !approved.keys.contains(key))
            {
                return Err(HostKeyError::Tool(
                    "SSH host keys changed after approval; an approved key is missing or replaced; no connection was opened".into(),
                ));
            }
            for key in &current.identity.keys {
                if approved.keys.contains(key) && !observed.contains(key) {
                    observed.push(key.clone());
                }
            }
            if approved.keys.iter().all(|key| observed.contains(key)) {
                // ssh-keyscan can succeed with a partial set when one of its
                // independent algorithm connections times out. Additional keys
                // discovered later remain untrusted, even on the same host.
                current.identity = approved.clone();
                let lookup = lookup_name(host, port);
                current.known_host_lines = approved
                    .keys
                    .iter()
                    .map(|key| format!("{lookup} {} {}", key.algorithm, key.encoded))
                    .collect();
                current
                    .known
                    .retain(|entry| approved.keys.contains(&entry.key));
                return Ok(current);
            }
            if attempt == 2 {
                let missing = approved
                    .keys
                    .iter()
                    .filter(|key| !observed.contains(key))
                    .map(PresentedKey::describe)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(HostKeyError::Tool(format!(
                    "could not read all approved SSH host keys after three scans; no connection was opened; missing approved keys: {missing}"
                )));
            }
            runner.pause(std::time::Duration::from_secs(1));
        }
        unreachable!()
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
        self.preflight_selected_with(host, port, runner, None)
    }

    fn compare_direct(
        &self,
        host: &str,
        port: u16,
        tunneled: &[KeyLine],
        runner: &impl Runner,
    ) -> Result<Vec<String>, HostKeyError> {
        let selected = scan_types(tunneled.iter().map(|key| key.algorithm.as_str()))?;
        let started = std::time::Instant::now();
        let unavailable = || {
            vec!["Direct client host-key probe unavailable; discovery and deployment use the existing backend tunnel.".into()]
        };
        let mut direct = Vec::new();
        let mut complete_output = false;
        let mut observed_family = [false; 2];
        // Explicit families are essential: ssh-keyscan may select an
        // unreachable IPv6 address without probing a reachable IPv4 identity.
        // Each family is checked even if the other already matches.
        for (types, per_probe) in [
            (selected.join(","), std::time::Duration::from_millis(750)),
            (
                "ed25519,ecdsa,rsa".into(),
                std::time::Duration::from_millis(500),
            ),
            (
                "ed25519-sk,ecdsa-sk".into(),
                std::time::Duration::from_millis(125),
            ),
            (
                "mldsa44-ed25519".into(),
                std::time::Duration::from_millis(125),
            ),
        ] {
            for (family_index, family) in ["-4", "-6"].iter().enumerate() {
                if observed_family[family_index] {
                    continue;
                }
                let remaining =
                    std::time::Duration::from_secs(3).saturating_sub(runner.elapsed(started));
                if remaining.is_zero() {
                    break;
                }
                let result = runner.run_bounded(
                    &self.ssh_keyscan,
                    &[
                        (*family).into(),
                        "-T".into(),
                        "1".into(),
                        "-p".into(),
                        port.to_string().into(),
                        "-t".into(),
                        types.clone().into(),
                        "--".into(),
                        host.into(),
                    ],
                    remaining.min(per_probe),
                );
                if let Ok(output) = result {
                    let keys = parse_key_lines(&output.stdout);
                    if keys.is_empty() {
                        continue;
                    }
                    // Inspect partial/failed output before any further probe:
                    // neither a matching family nor retry may hide a mismatch.
                    for key in &keys {
                        if !tunneled.iter().any(|other| other.same_key(key)) {
                            return Err(HostKeyError::Tool(format!(
                                "SSH HOST KEY ROUTE MISMATCH for {host}:{port}: direct and backend-tunneled {} keys differ; no authenticated target connection was opened",
                                key.algorithm
                            )));
                        }
                    }
                    observed_family[family_index] = true;
                    complete_output |= output.success;
                    direct.extend(keys);
                }
            }
        }
        if direct.is_empty() {
            return Ok(unavailable());
        }
        let complete = complete_output
            && tunneled
                .iter()
                .all(|key| direct.iter().any(|other| other.same_key(key)));
        if !complete {
            return Ok(vec!["Direct client host-key probe was partial; observed keys match the tunnel, and deployment uses the existing backend tunnel.".into()]);
        }
        Ok(Vec::new())
    }

    fn preflight_selected_with(
        &self,
        host: &str,
        port: u16,
        runner: &impl Runner,
        approved: Option<&[PresentedKey]>,
    ) -> Result<HostKeyPreflight, HostKeyError> {
        let lookup = lookup_name(host, port);
        let mut known = Vec::new();
        let mut recorded = Vec::new();
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
                let lines = parse_key_lines(&output.stdout);
                let numbers = found_lines(&output.stdout);
                for (index, line) in lines.iter().enumerate() {
                    recorded.push(KnownKey {
                        file: path.clone(),
                        line: numbers.get(index).copied(),
                        key: line.presented(),
                    });
                }
                known.extend(lines);
            }
        }
        let requested = match approved {
            Some(keys) => scan_types(keys.iter().map(|key| key.algorithm.as_str()))?,
            None => scan_types(known.iter().map(|key| key.algorithm.as_str()))?,
        };
        let (scan_host, scan_port) = match &self.route {
            Some(route) => route.endpoint(host, port)?,
            None => (host.to_owned(), port),
        };
        let started = std::time::Instant::now();
        let mut attempts = 0;
        let mut diagnostic = "no scan completed".to_owned();
        let scanned = loop {
            let remaining = DISCOVERY_BUDGET.saturating_sub(runner.elapsed(started));
            if attempts == MAX_DISCOVERY_ATTEMPTS || remaining < std::time::Duration::from_secs(2) {
                return Err(HostKeyError::Tool(format!(
                    "ssh-keyscan failed after {attempts} attempts within the 60-second discovery budget: {diagnostic}"
                )));
            }
            // Prefer Ed25519 for bootstrap; fall back one type at a time.
            // Existing pins and explicit approvals select only their types.
            let key_types = if requested.is_empty() {
                UNKNOWN_SCAN_TYPES[attempts % UNKNOWN_SCAN_TYPES.len()].to_owned()
            } else {
                requested.join(",")
            };
            attempts += 1;
            let timeout = remaining.min(std::time::Duration::from_secs(10));
            let scan = runner.run_bounded(
                &self.ssh_keyscan,
                &[
                    "-T".into(),
                    // Reserve a second for normal exit and pipe drain within
                    // the unchanged hard wall deadline. Subsecond fractions
                    // cannot extend ssh-keyscan's whole-second timeout.
                    (timeout.as_secs() - 1).to_string().into(),
                    "-p".into(),
                    scan_port.to_string().into(),
                    "-t".into(),
                    key_types.into(),
                    "--".into(),
                    scan_host.clone().into(),
                ],
                timeout,
            )?;
            let scanned = parse_key_lines(&scan.stdout);
            // A failed multi-algorithm scan can still emit keys. Inspect those
            // immediately: never retry away an observed key replacement.
            if !scanned.is_empty() {
                break scanned;
            }
            diagnostic = if scan.success {
                "successful ssh-keyscan produced no host keys".into()
            } else {
                scan.diagnostic
            };
            if attempts < MAX_DISCOVERY_ATTEMPTS {
                let delay =
                    DISCOVERY_DELAY.min(DISCOVERY_BUDGET.saturating_sub(runner.elapsed(started)));
                if !delay.is_zero() {
                    runner.pause(delay);
                }
            }
        };
        let connection_warnings = if self.route.is_some() {
            self.compare_direct(host, port, &scanned, runner)?
        } else {
            Vec::new()
        };
        let matching: Vec<KeyLine> = scanned
            .iter()
            .filter(|candidate| known.iter().any(|entry| entry.same_key(candidate)))
            .cloned()
            .collect();
        if !known.is_empty() && matching.is_empty() {
            let mut offered = scanned.iter().map(KeyLine::presented).collect::<Vec<_>>();
            offered.sort_by(|a, b| (&a.algorithm, &a.encoded).cmp(&(&b.algorithm, &b.encoded)));
            offered.dedup();
            return Err(HostKeyError::Changed(Box::new(ChangedHostKey {
                host: host.into(),
                port,
                expected: recorded,
                offered,
            })));
        }
        let status = if known.is_empty() {
            HostKeyStatus::Unknown
        } else {
            HostKeyStatus::Known
        };
        // Approval validation must inspect every observed key, including a
        // replacement alongside another matching known key.
        let mut accepted = if known.is_empty() || approved.is_some() {
            scanned
        } else {
            matching
        };
        // ssh-keyscan reports keys in no fixed order. Sorted, the identity the
        // operator approved compares equal to a later scan of the same keys.
        accepted.sort_by(|a, b| (&a.algorithm, &a.encoded).cmp(&(&b.algorithm, &b.encoded)));
        accepted.dedup_by(|a, b| a.same_key(b));
        let identity = HostIdentity {
            host: host.into(),
            port,
            keys: accepted.iter().map(KeyLine::presented).collect(),
            other_names_with_keys: aliases(&self.known_hosts, &accepted)?,
        };
        let known = recorded
            .into_iter()
            .filter(|entry| {
                accepted.iter().any(|key| {
                    key.algorithm == entry.key.algorithm && key.encoded == entry.key.encoded
                })
            })
            .collect();
        Ok(HostKeyPreflight {
            identity,
            status,
            known,
            connection_warnings,
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

// Names accepted by ssh-keyscan -t, ordered by bootstrap preference.
const UNKNOWN_SCAN_TYPES: &[&str] = &[
    "ed25519",
    "ecdsa",
    "rsa",
    "ed25519-sk",
    "ecdsa-sk",
    "mldsa44-ed25519",
];

fn scan_types<'a>(algorithms: impl Iterator<Item = &'a str>) -> Result<Vec<String>, HostKeyError> {
    let mut types = BTreeSet::new();
    for algorithm in algorithms {
        let key_type = match algorithm {
            "ssh-ed25519" => "ed25519",
            "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => "rsa",
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => "ecdsa",
            "sk-ssh-ed25519@openssh.com" => "ed25519-sk",
            "sk-ecdsa-sha2-nistp256@openssh.com" => "ecdsa-sk",
            "ssh-mldsa44-ed25519@openssh.com" => "mldsa44-ed25519",
            _ => {
                return Err(HostKeyError::Tool(format!(
                    "unsupported recorded SSH host-key algorithm: {algorithm}"
                )));
            }
        };
        types.insert(key_type.to_owned());
    }
    Ok(types.into_iter().collect())
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

/// The line numbers `ssh-keygen -F` reports, one per key it prints:
/// `# Host example found: line 10`.
fn found_lines(bytes: &[u8]) -> Vec<usize> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| line.strip_prefix("# Host "))
        .filter_map(|rest| rest.rsplit_once("found: line "))
        .filter_map(|(_, number)| number.trim().parse().ok())
        .collect()
}

pub(crate) fn lookup_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.into()
    } else {
        format!("[{host}]:{port}")
    }
}

mod persist;
pub(crate) mod runner;
#[cfg(test)]
use runner::Output;
use runner::{ProcessRunner, Runner};

#[cfg(test)]
mod tests;
