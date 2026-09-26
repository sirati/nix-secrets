use crate::{
    Decision, Frame, FrameError, FrameKind, HostKeyDecision, HostKeyError, HostKeyPreflight,
    HostKeyStatus, HostKeyVerifier,
};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

pub mod identity;
pub use identity::Offer;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum SshError {
    HostKey(HostKeyError),
    Io(io::Error),
    Protocol(FrameError),
    MissingPipe,
    /// ssh ended before the receiver answered; carries what ssh said.
    Disconnected {
        destination: String,
        stderr: String,
    },
}
impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostKey(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::MissingPipe => f.write_str("SSH pipe unavailable"),
            Self::Disconnected { destination, stderr } => {
                let cause = if stderr.contains("Too many authentication failures")
                    || stderr.contains("Permission denied")
                {
                    "authentication failed: the server did not accept the offered key. Check that the forwarder key is authorized for this account on the target"
                } else if stderr.contains("Connection refused")
                    || stderr.contains("Connection timed out")
                    || stderr.contains("No route to host")
                    || stderr.contains("Could not resolve")
                {
                    "the target could not be reached"
                } else if stderr.contains("Host key verification failed") {
                    "the host key did not match the one approved"
                } else {
                    "the connection closed before the receiver answered"
                };
                write!(f, "SSH to {destination} failed: {cause}.")?;
                let stderr = stderr.trim();
                if !stderr.is_empty() {
                    write!(f, " ssh said: {stderr}")?;
                }
                Ok(())
            }
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
    /// The only keys offered. Empty: ssh's own defaults.
    pub identities: Vec<Offer>,
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
        // Offering only the forwarder key keeps an agent with many keys from
        // hitting the server's MaxAuthTries. For an agent key ssh gets its
        // public half, and asks the agent to sign with exactly that key.
        let mut identity_arguments: Vec<OsString> = Vec::new();
        for (index, offer) in self.identities.iter().enumerate() {
            let file = match offer {
                Offer::File(path) => path.clone(),
                Offer::Agent(line) => {
                    let file = pin.directory.join(format!("identity-{index}.pub"));
                    let mut output = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .open(&file)?;
                    writeln!(output, "{line}")?;
                    file
                }
            };
            identity_arguments.push("-o".into());
            identity_arguments.push(format!("IdentityFile={}", file.display()).into());
        }
        if !self.identities.is_empty() {
            identity_arguments.extend(["-o".into(), "IdentitiesOnly=yes".into()]);
        }
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
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            // One authenticated connection per session: no password or
            // keyboard prompt, and no connection sharing with other ssh.
            .args(["-o", "PreferredAuthentications=publickey", "-o", "ControlMaster=no", "-o", "ControlPath=none"])
            .args(identity_arguments)
            .arg("--")
            .arg(&self.destination)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take().ok_or(SshError::MissingPipe)?;
        let output = child.stdout.take().ok_or(SshError::MissingPipe)?;
        let mut error_pipe = child.stderr.take().ok_or(SshError::MissingPipe)?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = error_pipe.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                if let Ok(mut text) = collected.lock() {
                    if text.len() < 64 * 1024 {
                        text.extend_from_slice(&buffer[..read]);
                    }
                }
            }
        });
        Ok(SshSession {
            child,
            input,
            output,
            stderr,
            destination: format!(
                "{}:{}",
                self.destination.to_string_lossy(),
                self.port
            ),
            _pin: pin,
        })
    }
}

pub struct SshSession {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    stderr: Arc<Mutex<Vec<u8>>>,
    destination: String,
    _pin: TemporaryKnownHosts,
}

impl SshSession {
    /// Turns an I/O failure on ssh's pipes into what ssh reported.
    fn explain(&mut self, error: FrameError) -> SshError {
        let broken = matches!(
            &error,
            FrameError::Io(io) if matches!(
                io.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe
            )
        );
        if !broken {
            return SshError::Protocol(error);
        }
        // ssh has exited or is exiting; its stderr is complete then.
        for _ in 0..50 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        let stderr = self
            .stderr
            .lock()
            .map(|text| String::from_utf8_lossy(&text).into_owned())
            .unwrap_or_default();
        SshError::Disconnected {
            destination: self.destination.clone(),
            stderr,
        }
    }

    pub fn open(&mut self, kind: FrameKind) -> Result<(), SshError> {
        if !matches!(kind, FrameKind::OpenManager | FrameKind::OpenDeployer) {
            return Err(SshError::Protocol(FrameError::Invalid("invalid open mode")));
        }
        Frame {
            kind,
            payload: Vec::new(),
        }
        .write_to(&mut self.input)
        .map_err(|error| self.explain(error))?;
        let response = Frame::read_from(&mut self.output).map_err(|error| self.explain(error))?;
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
        .write_to(&mut self.input)
        .map_err(|error| self.explain(error))?;
        Ok(())
    }
    pub fn receive(&mut self) -> Result<Frame, SshError> {
        Frame::read_from(&mut self.output).map_err(|error| self.explain(error))
    }
    pub fn close_write(&mut self) -> Result<(), SshError> {
        Frame {
            kind: FrameKind::Close,
            payload: Vec::new(),
        }
        .write_to(&mut self.input)
        .map_err(|error| self.explain(error))?;
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
