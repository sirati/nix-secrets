use crate::command::CommandSpec;
use crate::socket::connect_verified;
use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{Request, Response};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Bump this when the backend protocol or its persisted document format becomes
// incompatible with a running backend. The socket name keeps older processes
// and their active clients untouched while a compatible backend starts.
const BACKEND_COMPATIBILITY_VERSION: u32 = 20;

pub fn socket_name(repository: &Path) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    repository.hash(&mut hasher);
    format!(
        "backend-v{BACKEND_COMPATIBILITY_VERSION}-{:016x}.sock",
        hasher.finish()
    )
}

pub trait Launcher {
    type Guard;
    fn start(&mut self, command: &CommandSpec) -> io::Result<Self::Guard>;
    fn startup_error(&mut self, _guard: &mut Self::Guard) -> io::Result<Option<String>> {
        Ok(None)
    }
}

pub struct ProcessLauncher {
    kill_on_drop: bool,
    socket_to_remove: Option<std::path::PathBuf>,
}

pub struct ProcessGuard {
    child: Child,
    diagnostics: [Arc<Mutex<Vec<u8>>>; 2],
    readers: Vec<thread::JoinHandle<()>>,
    kill_on_drop: bool,
    socket_to_remove: Option<std::path::PathBuf>,
}

impl ProcessLauncher {
    pub fn persistent() -> Self {
        Self {
            kill_on_drop: false,
            socket_to_remove: None,
        }
    }

    pub fn ephemeral(socket: &Path) -> Self {
        Self {
            kill_on_drop: true,
            socket_to_remove: Some(socket.to_owned()),
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.kill_on_drop {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(socket) = &self.socket_to_remove {
                let _ = remove_stale_socket(socket);
            }
        }
    }
}

impl Launcher for ProcessLauncher {
    type Guard = ProcessGuard;
    fn start(&mut self, command: &CommandSpec) -> io::Result<ProcessGuard> {
        let mut child = command
            .command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Backend launchers (including SSH and nix run) outlive startup. Drain
        // their output for their entire lifetime without touching the TUI.
        let diagnostics = [
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        ];
        let readers = vec![
            capture_diagnostics(child.stdout.take().unwrap(), diagnostics[0].clone()),
            capture_diagnostics(child.stderr.take().unwrap(), diagnostics[1].clone()),
        ];
        Ok(ProcessGuard {
            child,
            diagnostics,
            readers,
            kill_on_drop: self.kill_on_drop,
            socket_to_remove: self.socket_to_remove.clone(),
        })
    }

    fn startup_error(&mut self, guard: &mut ProcessGuard) -> io::Result<Option<String>> {
        let Some(status) = guard.child.try_wait()? else {
            return Ok(None);
        };
        for reader in guard.readers.drain(..) {
            let _ = reader.join();
        }
        let text = guard
            .diagnostics
            .iter()
            .map(|buffer| {
                String::from_utf8_lossy(&buffer.lock().unwrap())
                    .trim()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n");
        Ok(Some(format!(
            "backend launcher exited with {status}: {}",
            text.trim()
        )))
    }
}

fn capture_diagnostics(
    mut reader: impl Read + Send + 'static,
    captured: Arc<Mutex<Vec<u8>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let mut captured = captured.lock().unwrap();
                    let available = (16 * 1024usize).saturating_sub(captured.len());
                    captured.extend_from_slice(&buffer[..count.min(available)]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

pub struct Connection<G> {
    pub stream: UnixStream,
    _backend: Option<G>,
}

pub fn connect_or_start<L: Launcher>(
    path: &Path,
    command: &CommandSpec,
    launcher: &mut L,
    timeout: Duration,
) -> io::Result<Connection<L::Guard>> {
    match connect_ready(path) {
        Ok(stream) => {
            return Ok(Connection {
                stream,
                _backend: None,
            })
        }
        Err(error) if retryable(&error) => {}
        Err(error) => return Err(error),
    }
    remove_stale_socket(path)?;
    let mut guard = launcher.start(command)?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(error) = launcher.startup_error(&mut guard)? {
            return Err(io::Error::other(error));
        }
        match connect_ready(path) {
            Ok(stream) => {
                return Ok(Connection {
                    stream,
                    _backend: Some(guard),
                })
            }
            Err(error) if retryable(&error) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) if retryable(&error) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("backend did not publish a valid socket: {error}"),
                ));
            }
            Err(error) => return Err(error),
        }
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
    )
}

fn connect_ready(path: &Path) -> io::Result<UnixStream> {
    let mut stream = connect_verified(path)?;
    // An SSH stream-local forward publishes its local socket before the
    // remote backend has finished evaluating Nix and binding its socket.
    // A round trip makes the backend itself, rather than the forward, the
    // readiness boundary.
    // A remote SSH round trip can take well over half a second even when the
    // backend is ready (for example when a client crosses a mesh network).
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write_json(&mut stream, &Request::List)?;
    match read_json::<Response>(&mut stream)? {
        Some(Response::Secrets { .. }) => {}
        Some(Response::Error { message }) => {
            return Err(io::Error::other(format!(
                "backend readiness probe failed: {message}"
            )))
        }
        Some(_) => {
            return Err(io::Error::other(
                "backend readiness probe returned an unexpected response",
            ))
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend closed during readiness probe",
            ))
        }
    }
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to replace an untrusted backend path",
        ));
    }
    fs::remove_file(path)
}

#[cfg(test)]
mod tests;
