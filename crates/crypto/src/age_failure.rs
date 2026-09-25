//! Readable, secret-free descriptions of failed age runs.
//!
//! age prints only its own diagnostics on stderr: plaintext goes to stdout,
//! and plugin traffic reaches stderr only with `AGEDEBUG=plugin`, which the
//! provider removes from the child environment. The text is still bounded,
//! stripped of control characters, and redacted of key-shaped tokens before
//! it is shown.
use std::{
    ffi::{OsStr, OsString},
    fmt,
    io::Read,
    path::PathBuf,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const SHOWN_CHARACTERS: usize = 600;
pub(crate) const CAPTURED_BYTES: u64 = 16 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct AgeFailure {
    /// What the caller was doing, such as `decrypting host.services.x.y`.
    pub operation: Option<String>,
    pub status: String,
    pub stderr: String,
    /// Diagnostics from `op` when the 1Password plugin failed.
    pub op_diagnostic: Option<String>,
    pub hint: Option<String>,
}

impl fmt::Display for AgeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(operation) = &self.operation {
            write!(formatter, "{operation} failed: ")?;
        }
        write!(formatter, "age exited with {}", self.status)?;
        if !self.stderr.is_empty() {
            write!(formatter, ": {}", self.stderr)?;
        }
        if let Some(diagnostic) = &self.op_diagnostic {
            write!(formatter, "\n{diagnostic}")?;
        }
        if let Some(hint) = &self.hint {
            write!(formatter, "\nHint: {hint}")?;
        }
        Ok(())
    }
}

impl AgeFailure {
    pub(crate) fn new(status: ExitStatus, stderr: &[u8]) -> Self {
        let stderr = clean(stderr);
        let hint = hint_for(&stderr).map(str::to_owned);
        Self {
            operation: None,
            status: describe_status(status),
            stderr,
            op_diagnostic: None,
            hint,
        }
    }

    /// The 1Password plugin discards `op`'s stderr, so rerun a harmless `op`
    /// command from the same PATH to recover its message and location.
    pub(crate) fn probe_one_password(&mut self, op_program: &OsStr) {
        if !self.stderr.contains("1p plugin") {
            return;
        }
        let location = resolve(op_program);
        let shown = location
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| op_program.to_string_lossy().into_owned());
        let Some(path) = location else {
            self.op_diagnostic = Some(format!("op: {shown} was not found in PATH"));
            self.hint = Some(
                "install the 1Password CLI; on NixOS enable programs._1password so \
                 /run/wrappers/bin/op exists"
                    .into(),
            );
            return;
        };
        let Some(message) = run_probe(&path) else {
            return;
        };
        if message.is_empty() {
            return;
        }
        let hint = if message.contains("connecting to desktop app timed out") {
            Some(APP_UNREACHABLE.to_owned())
        } else if message.contains("connecting to desktop app") {
            Some(format!(
                "the 1Password app rejected {shown}; it accepts only an op that is setgid \
                 onepassword-cli. On NixOS enable programs._1password so /run/wrappers/bin/op \
                 exists and precedes other op binaries in PATH"
            ))
        } else {
            hint_for(&message).map(str::to_owned)
        };
        self.op_diagnostic = Some(format!("op ({shown}): {message}"));
        if hint.is_some() {
            self.hint = hint;
        }
    }
}

const APP_UNREACHABLE: &str = "start and unlock the 1Password app and enable Settings > \
     Developer > Integrate with 1Password CLI";

fn hint_for(text: &str) -> Option<&'static str> {
    const HINTS: &[(&str, &str)] = &[
        ("connecting to desktop app timed out", APP_UNREACHABLE),
        (
            "connecting to desktop app",
            "op cannot reach the 1Password app; the app accepts only an op that is setgid \
             onepassword-cli (on NixOS enable programs._1password so /run/wrappers/bin/op exists)",
        ),
        (
            "1Password app is locked",
            "unlock the 1Password app and retry",
        ),
        (
            "authorization prompt dismissed",
            "approve the 1Password authorization prompt and retry",
        ),
        (
            "authorization took too long",
            "the 1Password authorization prompt timed out; retry and approve it",
        ),
        (
            "authorization timeout",
            "the 1Password authorization prompt timed out; retry and approve it",
        ),
        (
            "no accounts configured",
            "sign in to a 1Password account in the desktop app",
        ),
        (
            "not currently signed in",
            "enable Settings > Developer > Integrate with 1Password CLI, or run op signin",
        ),
        (
            "no identity matched any of the recipients",
            "none of the available identities is a recipient of this secret",
        ),
        (
            "1p\" plugin not found",
            "age-plugin-1p is not in PATH; use the nix-secrets-1password package",
        ),
    ];
    HINTS
        .iter()
        .find(|(needle, _)| text.contains(needle))
        .map(|(_, hint)| *hint)
}

fn describe_status(status: ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit code {code}"),
        (None, Some(signal)) => format!("signal {signal}"),
        (None, None) => "an unknown status".into(),
    }
}

/// Bounds, flattens, and redacts subprocess diagnostics for display.
pub(crate) fn clean(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.contains("report unexpected or unhelpful errors"))
        .map(|line| {
            if line.contains("PRIVATE KEY") {
                "[redacted key material]".to_owned()
            } else {
                line.split(' ')
                    .map(|word| {
                        if word.starts_with("AGE-SECRET-KEY-") || word.starts_with("AGE-PLUGIN-") {
                            "[redacted]"
                        } else {
                            word
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            }
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let flat: String = lines
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    if flat.chars().count() > SHOWN_CHARACTERS {
        let mut bounded: String = flat.chars().take(SHOWN_CHARACTERS).collect();
        bounded.push('…');
        bounded
    } else {
        flat
    }
}

fn resolve(program: &OsStr) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let program = PathBuf::from(program);
    if program.components().count() > 1 {
        return Some(program);
    }
    let path = std::env::var_os("PATH").unwrap_or_else(OsString::new);
    std::env::split_paths(&path)
        .map(|directory| directory.join(&program))
        .find(|candidate| {
            candidate
                .metadata()
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
}

/// `op account list` needs no vault access and prints no secrets; its stdout
/// is discarded and only stderr is kept.
fn run_probe(path: &PathBuf) -> Option<String> {
    let mut child = Command::new(path)
        .args(["account", "list", "--format=json"])
        .env_remove("AGEDEBUG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut stderr = child.stderr.take()?;
    let reader = std::thread::spawn(move || {
        let mut captured = Vec::new();
        let _ = stderr
            .by_ref()
            .take(CAPTURED_BYTES)
            .read_to_end(&mut captured);
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        captured
    });
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Some("did not answer within 10 seconds".into());
            }
        }
    }
    let captured = reader.join().ok()?;
    Some(clean(strip_log_prefix(&captured)))
}

/// op prefixes errors with `[ERROR] YYYY/MM/DD HH:MM:SS `.
fn strip_log_prefix(raw: &[u8]) -> &[u8] {
    let prefix = b"[ERROR] ";
    if raw.starts_with(prefix) && raw.len() > prefix.len() + 20 {
        &raw[prefix.len() + 20..]
    } else {
        raw
    }
}

#[cfg(test)]
mod tests;
