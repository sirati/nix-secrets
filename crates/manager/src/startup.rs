use crate::command::CommandSpec;
use crate::socket::connect_verified;
use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{Request, Response};
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub trait Launcher {
    type Guard;
    fn start(&mut self, command: &CommandSpec) -> io::Result<Self::Guard>;
}

pub struct ProcessLauncher {
    kill_on_drop: bool,
    socket_to_remove: Option<std::path::PathBuf>,
}

pub struct ProcessGuard {
    child: Child,
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
        let child = command.command().stdin(Stdio::piped()).spawn()?;
        Ok(ProcessGuard {
            child,
            kill_on_drop: self.kill_on_drop,
            socket_to_remove: self.socket_to_remove.clone(),
        })
    }
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
    let guard = launcher.start(command)?;
    let deadline = Instant::now() + timeout;
    loop {
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
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "manager-start-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    struct FakeLauncher {
        path: std::path::PathBuf,
        starts: usize,
    }
    impl Launcher for FakeLauncher {
        type Guard = std::thread::JoinHandle<()>;
        fn start(&mut self, _command: &CommandSpec) -> io::Result<Self::Guard> {
            self.starts += 1;
            let listener = UnixListener::bind(&self.path)?;
            Ok(std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let request: Request = read_json(&mut stream).unwrap().unwrap();
                    assert!(matches!(request, Request::List));
                    write_json(
                        &mut stream,
                        &Response::Secrets {
                            entries: Default::default(),
                        },
                    )
                    .unwrap();
                }
            }))
        }
    }

    #[test]
    fn starts_once_then_connects_to_same_user_backend() {
        let path = path();
        let mut launcher = FakeLauncher {
            path: path.clone(),
            starts: 0,
        };
        let spec = CommandSpec {
            program: "unused".into(),
            arguments: vec![],
        };
        let connection = match connect_or_start(&path, &spec, &mut launcher, Duration::from_secs(1))
        {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("startup failed: {error}"),
        };
        assert_eq!(launcher.starts, 1);
        drop(connection.stream);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn waits_until_a_forwarded_socket_reaches_the_backend() {
        struct DelayedForward {
            path: std::path::PathBuf,
        }

        impl Launcher for DelayedForward {
            type Guard = std::thread::JoinHandle<()>;

            fn start(&mut self, _command: &CommandSpec) -> io::Result<Self::Guard> {
                let listener = UnixListener::bind(&self.path)?;
                Ok(std::thread::spawn(move || {
                    let (first, _) = listener.accept().unwrap();
                    drop(first); // SSH accepted locally; remote socket is not ready.
                    let (mut second, _) = listener.accept().unwrap();
                    let request: Request = read_json(&mut second).unwrap().unwrap();
                    assert!(matches!(request, Request::List));
                    write_json(
                        &mut second,
                        &Response::Secrets {
                            entries: Default::default(),
                        },
                    )
                    .unwrap();
                }))
            }
        }

        let path = path();
        let spec = CommandSpec {
            program: "unused".into(),
            arguments: vec![],
        };
        let connection = connect_or_start(
            &path,
            &spec,
            &mut DelayedForward { path: path.clone() },
            Duration::from_secs(1),
        )
        .unwrap();
        drop(connection);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn ephemeral_tunnel_removes_only_its_socket_on_exit() {
        let socket = path();
        let listener = UnixListener::bind(&socket).unwrap();
        let command = CommandSpec {
            program: "sleep".into(),
            arguments: vec!["30".into()],
        };
        let mut launcher = ProcessLauncher::ephemeral(&socket);
        let guard = launcher.start(&command).unwrap();
        drop(guard);
        assert!(!socket.exists());
        drop(listener);
    }
}
