use rustix::net::sockopt::socket_peercred;
use rustix::process::geteuid;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

pub fn connect_verified(path: &Path) -> io::Result<UnixStream> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(invalid("backend path is not a Unix socket"));
    }

    let effective_uid = geteuid();
    if metadata.uid() != effective_uid.as_raw() {
        return Err(denied("backend socket is owned by another user"));
    }

    let stream = UnixStream::connect(path)?;
    let peer = socket_peercred(&stream).map_err(io::Error::from)?;
    if peer.uid != effective_uid {
        return Err(denied("backend process runs as another user"));
    }
    Ok(stream)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn path(name: &str) -> std::path::PathBuf {
        let id = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("nix-secrets-{name}-{}-{id}", std::process::id()))
    }

    #[test]
    fn accepts_a_same_user_socket_and_peer() {
        let path = path("valid");
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind test socket: {error}"),
        };
        let server = thread::spawn(move || listener.accept().unwrap());
        let stream = connect_verified(&path).unwrap();
        drop(stream);
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_regular_files_before_connecting() {
        let path = path("file");
        File::create(&path).unwrap();
        let error = connect_verified(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_a_symlink_to_a_socket() {
        let target = path("target");
        let link = path("link");
        File::create(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = connect_verified(&link).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
    }
}
