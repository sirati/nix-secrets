use crate::backend::{Request, Response};
use crate::framing::{read_json, write_json};
use rustix::process::geteuid;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

pub(super) fn prepare_socket_path(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket has no parent",
        ));
    };
    fs::create_dir_all(parent)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "socket path is not a socket",
                ));
            }
            if metadata.uid() != geteuid().as_raw() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socket has a different owner",
                ));
            }
            match UnixStream::connect(path) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
                    stream.set_write_timeout(Some(std::time::Duration::from_secs(3)))?;
                    write_json(&mut stream, &Request::List)?;
                    if matches!(
                        read_json::<Response>(&mut stream)?,
                        Some(Response::Secrets { .. })
                    ) {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "a live backend already owns the socket",
                        ));
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "socket is live but does not speak the backend protocol",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(error) => return Err(error),
            }
            fs::remove_file(path)
        }
    }
}
