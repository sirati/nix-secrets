//! Whether the stored ciphertext of a secret is already in git.
//!
//! Overwriting a value that exists only in the working tree destroys it, so
//! the TUI warns first. The check compares the current record with the one in
//! `HEAD:<store file>`; older commits are not searched, because a value that
//! was committed and later replaced without a commit is not recoverable from
//! HEAD either, and walking history would grow with the repository.
use super::*;
use std::process::{Command, Stdio};

/// How the current record of one identifier relates to git.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CommitState {
    /// No value is stored; nothing can be lost.
    Unset,
    /// `HEAD` holds exactly this version and ciphertext.
    Committed,
    /// The value exists only in the working tree.
    Uncommitted,
    /// git could not answer; the caller must treat the value as uncommitted.
    Unknown { reason: String },
}

impl SecretStore {
    pub fn commit_state(&self, path: &SecretPath) -> Result<CommitState, StoreError> {
        let Some(current) = self.with_lock(false, |document| {
            Ok(document.secrets.get(&path.to_string()).cloned())
        })?
        else {
            return Ok(CommitState::Unset);
        };
        Ok(match self.committed_document() {
            Ok(committed) => {
                let same = committed
                    .secrets
                    .get(&path.to_string())
                    .is_some_and(|record| {
                        record.version_id == current.version_id
                            && record.age_ciphertext == current.age_ciphertext
                    });
                if same {
                    CommitState::Committed
                } else {
                    CommitState::Uncommitted
                }
            }
            Err(reason) => CommitState::Unknown { reason },
        })
    }

    /// Reads the store file as committed in `HEAD`.
    fn committed_document(&self) -> Result<StoreDocument, String> {
        let directory = self
            .path
            .parent()
            .ok_or("the store has no repository directory")?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("the store file name is not UTF-8")?;
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(["show", "--no-textconv"])
            // `./` resolves the path relative to the directory, not the
            // repository root, so a store in a subdirectory still works.
            .arg(format!("HEAD:./{name}"))
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("git could not be started: {error}"))?;
        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr);
            let message = message.trim();
            return Err(
                if message.contains("does not exist") || message.contains("exists on disk") {
                    format!("{name} is not in the last commit")
                } else if message.is_empty() {
                    format!("git show failed with {}", output.status)
                } else {
                    format!("git: {}", message.lines().next().unwrap_or(message))
                },
            );
        }
        let text = String::from_utf8(output.stdout)
            .map_err(|_| format!("the committed {name} is not UTF-8"))?;
        toml::from_str(&text).map_err(|error| format!("the committed {name} is invalid: {error}"))
    }
}

#[cfg(test)]
mod tests;
