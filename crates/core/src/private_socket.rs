//! Private, short-lived Unix sockets that the backend hands to one child
//! process: a fresh 0700 directory under the runtime directory holding one
//! 0600 socket. Dropping the value removes both.
use rustix::net::sockopt::socket_peercred;
use rustix::process::geteuid;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

pub struct PrivateSocket {
    directory: PathBuf,
    socket: PathBuf,
    listener: UnixListener,
}

impl PrivateSocket {
    /// Binds `<file>` in a new directory `<prefix>-<random>` under `runtime`.
    /// The listener is non-blocking.
    pub fn bind(runtime: &Path, prefix: &str, file: &str) -> io::Result<Self> {
        let mut random = [0; 12];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = runtime.join(format!("{prefix}-{name}"));
        DirBuilder::new().mode(0o700).create(&directory)?;
        // The mode is applied again in case the umask narrowed nothing but a
        // parent ACL widened it.
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let socket = directory.join(file);
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_dir(&directory);
                return Err(error);
            }
        };
        let private = Self {
            directory,
            socket,
            listener,
        };
        fs::set_permissions(&private.socket, fs::Permissions::from_mode(0o600))?;
        private.listener.set_nonblocking(true)?;
        Ok(private)
    }

    pub fn path(&self) -> &Path {
        &self.socket
    }

    /// Accepts one pending connection from a process of this user. Returns
    /// `None` when nothing is waiting; other users' connections are dropped.
    pub fn accept(&self) -> io::Result<Option<UnixStream>> {
        match self.listener.accept() {
            Ok((stream, _)) => {
                let peer = socket_peercred(&stream).map_err(io::Error::from)?;
                if peer.uid != geteuid() {
                    return Ok(None);
                }
                stream.set_nonblocking(false)?;
                Ok(Some(stream))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl Drop for PrivateSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir(&self.directory);
    }
}

/// Where the backend creates its private socket directories.
pub fn runtime_directory() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_dir())
        .unwrap_or_else(std::env::temp_dir)
}
