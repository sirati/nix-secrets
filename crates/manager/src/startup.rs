use crate::command::CommandSpec;
use crate::socket::connect_verified;
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

pub struct ProcessLauncher;

impl Launcher for ProcessLauncher {
    type Guard = Child;
    fn start(&mut self, command: &CommandSpec) -> io::Result<Child> {
        command.command().stdin(Stdio::null()).spawn()
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
    match connect_verified(path) {
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
        match connect_verified(path) {
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
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
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
                if let Ok((_stream, _)) = listener.accept() {
                    std::thread::sleep(Duration::from_millis(100));
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
}
