//! Secret requests: a process on the backend host asks the attached TUI for
//! a batch of plaintext values, which the operator approves once.
//!
//! Wire types shared by the backend, the TUI (which approves and decrypts),
//! and `nix-secrets with-secrets`/`pipe-secret` (which request and consume).
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

/// Most identifiers one request may name.
pub const MAX_REQUEST_IDENTIFIERS: usize = 256;
pub const MAX_REQUEST_REASON_BYTES: usize = 4096;
/// Longest argv shown for a process; the rest is cut.
const MAX_ARGV_BYTES: usize = 16 * 1024;
const MAX_ARGUMENTS: usize = 256;

/// A process as the backend saw it in `/proc`, never as it described itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessInfo {
    pub pid: u32,
    pub executable: Option<String>,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
}

impl ProcessInfo {
    /// Reads `/proc/<pid>`. Fields the kernel does not show are left empty.
    pub fn read(pid: u32) -> Self {
        let base = Path::new("/proc").join(pid.to_string());
        let link = |name: &str| {
            fs::read_link(base.join(name))
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        };
        let mut argv = Vec::new();
        if let Ok(mut cmdline) = fs::read(base.join("cmdline")) {
            if cmdline.last() == Some(&0) {
                cmdline.pop();
            }
            let mut total = 0;
            for argument in cmdline.split(|byte| *byte == 0) {
                total += argument.len() + 1;
                if argv.len() == MAX_ARGUMENTS || total > MAX_ARGV_BYTES {
                    argv.push("…".into());
                    break;
                }
                argv.push(String::from_utf8_lossy(argument).into_owned());
            }
            if cmdline.is_empty() {
                argv.clear();
            }
        }
        Self {
            pid,
            executable: link("exe"),
            argv,
            cwd: link("cwd"),
        }
    }
}

/// The parent of `pid`, from `/proc/<pid>/stat`.
pub fn parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may contain spaces and parentheses; the fields after
    // its last `)` are fixed: state, then the parent PID.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Whether `pid` is `ancestor` or one of its descendants.
pub fn is_same_or_descendant(pid: u32, ancestor: u32) -> bool {
    let mut current = pid;
    // Bounded: a PID chain cannot be longer than the process table, and a
    // stale read must not loop forever.
    for _ in 0..4096 {
        if current == ancestor {
            return true;
        }
        match parent_pid(current) {
            Some(parent) if parent != 0 && parent != current => current = parent,
            _ => return false,
        }
    }
    false
}

/// What the backend asks the TUI to approve.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRequest {
    pub id: String,
    pub identifiers: Vec<String>,
    /// Requester-supplied explanation, not verified by the backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_signature: Option<crate::ssh_auth::SignatureRequest>,
    /// The process that connected to the backend, read from `/proc`.
    pub requester: ProcessInfo,
    /// Its parent, which is usually the program that wants the values.
    pub parent: Option<ProcessInfo>,
}

/// One decrypted value. The encoding is erased when the value is dropped.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretValue {
    pub identifier: String,
    pub value_base64: String,
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.value_base64.zeroize();
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretValue")
            .field("identifier", &self.identifier)
            .field("value_base64", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "answer", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SecretAnswer {
    Approved { values: Vec<SecretValue> },
    Signed { reply: Vec<u8> },
    Denied { reason: String },
}

/// Requests on a session socket (`NIX_SECRETS_SESSION`).
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SessionRequest {
    Get { identifier: String },
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SessionResponse {
    Value { value_base64: String },
    Error { message: String },
}

impl Drop for SessionResponse {
    fn drop(&mut self) {
        if let Self::Value { value_base64 } = self {
            value_base64.zeroize();
        }
    }
}

impl std::fmt::Debug for SessionResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value { .. } => formatter.write_str("Value(<redacted>)"),
            Self::Error { message } => formatter.debug_tuple("Error").field(message).finish(),
        }
    }
}

/// The environment variable naming a session socket.
pub const SESSION_ENVIRONMENT: &str = "NIX_SECRETS_SESSION";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_this_process_from_proc() {
        let own = ProcessInfo::read(std::process::id());
        assert_eq!(own.pid, std::process::id());
        assert_eq!(
            own.cwd.as_deref().map(Path::new),
            Some(std::env::current_dir().unwrap().as_path())
        );
        assert!(own.executable.is_some());
        assert!(!own.argv.is_empty());
        assert_eq!(
            parent_pid(std::process::id()),
            Some(std::os::unix::process::parent_id())
        );
    }

    #[test]
    fn descendants_are_recognised_by_their_parent_chain() {
        let own = std::process::id();
        assert!(is_same_or_descendant(own, own));
        assert!(is_same_or_descendant(
            own,
            std::os::unix::process::parent_id()
        ));
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        assert!(is_same_or_descendant(child.id(), own));
        assert!(!is_same_or_descendant(own, child.id()));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn values_never_appear_in_debug_output() {
        let value = SecretValue {
            identifier: "host.services.a.b".into(),
            value_base64: "c2VjcmV0".into(),
        };
        assert!(!format!("{value:?}").contains("c2VjcmV0"));
        let response = SessionResponse::Value {
            value_base64: "c2VjcmV0".into(),
        };
        assert!(!format!("{response:?}").contains("c2VjcmV0"));
    }
}
