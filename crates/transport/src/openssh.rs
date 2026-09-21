use crate::{
    Decision, Frame, FrameError, FrameKind, HostKeyDecision, HostKeyError, HostKeyPreflight,
    HostKeyStatus, HostKeyVerifier,
};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum SshError {
    HostKey(HostKeyError),
    Io(io::Error),
    Protocol(FrameError),
    MissingPipe,
}
impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostKey(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::MissingPipe => f.write_str("SSH pipe unavailable"),
        }
    }
}
impl std::error::Error for SshError {}
impl From<HostKeyError> for SshError {
    fn from(value: HostKeyError) -> Self {
        Self::HostKey(value)
    }
}
impl From<io::Error> for SshError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<FrameError> for SshError {
    fn from(value: FrameError) -> Self {
        Self::Protocol(value)
    }
}

pub struct OpenSsh {
    pub program: OsString,
    pub destination: OsString,
    pub host: String,
    pub port: u16,
    pub verifier: HostKeyVerifier,
}

impl OpenSsh {
    pub fn connect(&self, decision: &mut impl HostKeyDecision) -> Result<SshSession, SshError> {
        let verified = self.verifier.verify(&self.host, self.port, decision)?;
        self.spawn(verified.known_host_lines)
    }

    pub fn connect_preflight(
        &self,
        preflight: HostKeyPreflight,
        unknown: Decision,
    ) -> Result<SshSession, SshError> {
        if preflight.identity.host != self.host || preflight.identity.port != self.port {
            return Err(SshError::HostKey(HostKeyError::Tool(
                "host-key preflight target mismatch".into(),
            )));
        }
        if preflight.status == HostKeyStatus::Unknown && unknown == Decision::Reject {
            return Err(SshError::HostKey(HostKeyError::UnknownRejected));
        }
        self.spawn(preflight.known_host_lines)
    }

    fn spawn(&self, known_host_lines: Vec<String>) -> Result<SshSession, SshError> {
        let pin = TemporaryKnownHosts::create(&known_host_lines)?;
        let mut child = Command::new(&self.program)
            .args([
                "-T",
                "-p",
                &self.port.to_string(),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "CheckHostIP=no",
                "-o",
                "UpdateHostKeys=no",
                "-o",
                "ConnectTimeout=15",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
            ])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", pin.file.display()))
            .args(["-o", "GlobalKnownHostsFile=/dev/null", "--"])
            .arg(&self.destination)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().ok_or(SshError::MissingPipe)?;
        let output = child.stdout.take().ok_or(SshError::MissingPipe)?;
        Ok(SshSession {
            child,
            input,
            output,
            _pin: pin,
        })
    }
}

pub struct SshSession {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    _pin: TemporaryKnownHosts,
}

impl SshSession {
    pub fn open(&mut self, kind: FrameKind) -> Result<(), SshError> {
        if !matches!(kind, FrameKind::OpenManager | FrameKind::OpenDeployer) {
            return Err(SshError::Protocol(FrameError::Invalid("invalid open mode")));
        }
        Frame {
            kind,
            payload: Vec::new(),
        }
        .write_to(&mut self.input)?;
        let response = Frame::read_from(&mut self.output)?;
        if response.kind != FrameKind::Data || !response.payload.is_empty() {
            return Err(SshError::Protocol(FrameError::Invalid(
                "receiver rejected open",
            )));
        }
        Ok(())
    }
    pub fn send(&mut self, bytes: &[u8]) -> Result<(), SshError> {
        Frame {
            kind: FrameKind::Data,
            payload: bytes.to_vec(),
        }
        .write_to(&mut self.input)?;
        Ok(())
    }
    pub fn receive(&mut self) -> Result<Frame, SshError> {
        Ok(Frame::read_from(&mut self.output)?)
    }
    pub fn close_write(&mut self) -> Result<(), SshError> {
        Frame {
            kind: FrameKind::Close,
            payload: Vec::new(),
        }
        .write_to(&mut self.input)?;
        Ok(())
    }
    pub fn wait(mut self) -> Result<std::process::ExitStatus, SshError> {
        Ok(self.child.wait()?)
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct TemporaryKnownHosts {
    directory: PathBuf,
    file: PathBuf,
}
impl TemporaryKnownHosts {
    fn create(lines: &[String]) -> io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        for _ in 0..128 {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let directory = base.join(format!(
                "nix-secrets-hostkey-{}-{nonce}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let result = fs::DirBuilder::new().mode(0o700).create(&directory);
            match result {
                Ok(()) => {
                    let file = directory.join("known_hosts");
                    let mut output = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .open(&file)?;
                    for line in lines {
                        writeln!(output, "{line}")?;
                    }
                    output.sync_all()?;
                    return Ok(Self { directory, file });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate host-key directory",
        ))
    }
}
impl Drop for TemporaryKnownHosts {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_file_is_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let directory;
        {
            let pin = TemporaryKnownHosts::create(&["host ssh-ed25519 AAAA".into()]).unwrap();
            directory = pin.directory.clone();
            assert_eq!(
                fs::metadata(&pin.file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::read_to_string(&pin.file).unwrap(),
                "host ssh-ed25519 AAAA\n"
            );
        }
        assert!(!std::path::Path::new(&directory).exists());
    }
}
