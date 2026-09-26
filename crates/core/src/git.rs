//! Commits the files the backend manages, signed through the frontend's
//! ssh-agent.
//!
//! Only `nix-secrets.toml` and `nix-secrets-profiles.toml` are ever staged or
//! committed. If anything else is already staged the commit is refused, so
//! the operator never commits unrelated work by accident; `git commit --
//! <paths>` would also leave it out, but silently, and a later `git commit`
//! would then pick it up unreviewed.
//!
//! Signing: repositories often sign with `gpg.format = ssh` and a program
//! such as 1Password's `op-ssh-sign`, which asks a local desktop app rather
//! than `SSH_AUTH_SOCK`. The backend may run elsewhere, so a signed commit
//! runs with `gpg.ssh.program=ssh-keygen`, which signs through the agent at
//! `SSH_AUTH_SOCK`, and that socket is a private proxy to the frontend's
//! agent (see [`agent`]). `user.signingkey` stays as configured.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub mod agent;

/// The files this backend writes, relative to the repository.
pub const MANAGED_FILES: [&str; 2] = ["nix-secrets.toml", "nix-secrets-profiles.toml"];

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitSummary {
    /// `git diff --stat HEAD` of the managed files, or of their full
    /// content when the repository has no commit yet.
    pub diff_stat: String,
    /// Managed files with changes, as `git status --porcelain` reports them.
    pub changed: Vec<String>,
    /// Other staged paths; a commit is refused while there are any.
    pub foreign_staged: Vec<String>,
    /// The message of `HEAD`, offered when amending.
    pub head_message: Option<String>,
    /// Whether commits are signed (`commit.gpgsign`).
    pub signs: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitOptions {
    pub message: String,
    pub amend: bool,
    pub signoff: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitResult {
    pub hash: String,
    /// The first line git printed, such as `[main 1a2b3c4] message`.
    pub output: String,
}

pub struct Repository {
    directory: PathBuf,
}

impl Repository {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn git(&self) -> Command {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(&self.directory)
            .stdin(Stdio::null())
            // Never open an editor or pager on the backend.
            .env("GIT_EDITOR", "true")
            .env("GIT_PAGER", "cat")
            .env("GIT_TERMINAL_PROMPT", "0");
        command
    }

    fn run(&self, arguments: &[&str]) -> Result<String, String> {
        let output = self
            .git()
            .args(arguments)
            .output()
            .map_err(|error| format!("git could not be started: {error}"))?;
        checked(output)
    }

    fn has_head(&self) -> bool {
        self.git()
            .args(["rev-parse", "--verify", "-q", "HEAD"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Managed files that exist or are tracked; git rejects pathspecs that
    /// match nothing.
    fn managed_paths(&self) -> Result<Vec<&'static str>, String> {
        let tracked = self.run(&["ls-files", "--", MANAGED_FILES[0], MANAGED_FILES[1]])?;
        Ok(MANAGED_FILES
            .into_iter()
            .filter(|file| {
                self.directory.join(file).exists() || tracked.lines().any(|line| line == *file)
            })
            .collect())
    }

    pub fn summary(&self) -> Result<CommitSummary, String> {
        let paths = self.managed_paths()?;
        let has_head = self.has_head();
        let mut summary = CommitSummary {
            signs: self
                .run(&["config", "--type=bool", "--get", "commit.gpgsign"])
                .is_ok_and(|value| value.trim() == "true"),
            foreign_staged: self.foreign_staged()?,
            ..CommitSummary::default()
        };
        if paths.is_empty() {
            return Ok(summary);
        }
        let mut status = vec!["status", "--porcelain=v1", "--untracked-files=all", "--"];
        status.extend(&paths);
        summary.changed = self.run(&status)?.lines().map(str::to_owned).collect();
        let mut diff = if has_head {
            vec!["diff", "--stat", "HEAD", "--"]
        } else {
            vec!["diff", "--stat", "--cached", "--"]
        };
        diff.extend(&paths);
        summary.diff_stat = self.run(&diff)?.trim_end().to_owned();
        let untracked = summary
            .changed
            .iter()
            .filter_map(|line| line.strip_prefix("?? "))
            .collect::<Vec<_>>();
        if !untracked.is_empty() {
            let note = format!("new: {}", untracked.join(", "));
            summary.diff_stat = if summary.diff_stat.is_empty() {
                note
            } else {
                format!("{}\n{note}", summary.diff_stat)
            };
        }
        if has_head {
            summary.head_message = self
                .run(&["log", "-1", "--format=%B", "HEAD"])
                .ok()
                .map(|message| message.trim_end().to_owned());
        }
        Ok(summary)
    }

    fn foreign_staged(&self) -> Result<Vec<String>, String> {
        let staged = if self.has_head() {
            self.run(&["diff", "--cached", "--name-only", "-z", "HEAD"])?
        } else {
            self.run(&["diff", "--cached", "--name-only", "-z", "--root"])
                .or_else(|_| self.run(&["ls-files", "-z", "--cached"]))?
        };
        Ok(staged
            .split('\0')
            .filter(|path| !path.is_empty() && !MANAGED_FILES.contains(path))
            .map(str::to_owned)
            .collect())
    }

    /// Stages the managed files and commits them. `agent` is the
    /// `SSH_AUTH_SOCK` for signing, if any.
    pub fn commit(
        &self,
        options: &CommitOptions,
        agent: Option<&Path>,
    ) -> Result<CommitResult, String> {
        let message = options.message.trim();
        if message.is_empty() && !options.amend {
            return Err("the commit message is empty".into());
        }
        let foreign = self.foreign_staged()?;
        if !foreign.is_empty() {
            return Err(format!(
                "other changes are staged, so nothing was committed; unstage them first: {}",
                foreign.join(", ")
            ));
        }
        let paths = self.managed_paths()?;
        if paths.is_empty() {
            return Err("there are no nix-secrets files to commit".into());
        }
        let mut add = vec!["add", "--"];
        add.extend(&paths);
        self.run(&add)?;
        let mut command = self.git();
        if agent.is_some() {
            command.args(["-c", "gpg.ssh.program=ssh-keygen"]);
        }
        command.arg("commit").arg("--quiet");
        if options.amend {
            command.arg("--amend");
            // An amend with an empty message keeps the one in HEAD.
            if message.is_empty() {
                command.arg("--no-edit");
            }
        }
        if options.signoff {
            command.arg("--signoff");
        }
        if !message.is_empty() {
            command.arg("--cleanup=strip").arg("-m").arg(message);
        }
        command.arg("--").args(&paths);
        // Without a relayed agent, git signs as the backend's own
        // configuration and environment would.
        if let Some(socket) = agent {
            command.env("SSH_AUTH_SOCK", socket);
        }
        let output = command
            .output()
            .map_err(|error| format!("git could not be started: {error}"))?;
        let stdout = checked(output)?;
        let hash = self.run(&["rev-parse", "HEAD"])?.trim().to_owned();
        let output = self
            .run(&["log", "-1", "--format=[%h] %s", "HEAD"])
            .map(|line| line.trim().to_owned())
            .unwrap_or_else(|_| stdout.lines().next().unwrap_or_default().to_owned());
        Ok(CommitResult { hash, output })
    }
}

fn checked(output: Output) -> Result<String, String> {
    if output.status.success() {
        return String::from_utf8(output.stdout).map_err(|_| "git printed non-UTF-8 output".into());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    Err(if stderr.is_empty() {
        format!("git failed with {}", output.status)
    } else {
        stderr.to_owned()
    })
}

#[cfg(test)]
mod tests;
