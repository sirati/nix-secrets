use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{Request, Response};
use rustix::fs::{CWD, FlockOperation, Mode, OFlags, flock, openat};
use rustix::net::sockopt::socket_peercred;
use rustix::process::geteuid;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

pub enum Disposition {
    Owner(File),
    Attached,
}

pub fn acquire_or_attach(socket: &Path) -> io::Result<Disposition> {
    let parent = socket
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket has no parent"))?;
    fs::create_dir_all(parent)?;
    let lock_path = socket.with_extension("lock");
    let lock = File::from(
        openat(
            CWD,
            &lock_path,
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io::Error::from)?,
    );
    let lock_metadata = lock.metadata()?;
    if !lock_metadata.is_file() || lock_metadata.uid() != geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "backend lock is not a regular file owned by this user",
        ));
    }
    loop {
        match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                if live_backend(socket)? {
                    return Ok(Disposition::Attached);
                }
                return Ok(Disposition::Owner(lock));
            }
            Err(error) if io::Error::from(error).kind() == io::ErrorKind::WouldBlock => {
                if live_backend(socket)? {
                    return Ok(Disposition::Attached);
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

pub fn watch_existing(socket: &Path, hold_channel: bool) -> io::Result<()> {
    let disconnected = Arc::new(AtomicBool::new(false));
    if hold_channel {
        let disconnected = Arc::clone(&disconnected);
        thread::spawn(move || {
            let mut stdin = io::stdin().lock();
            let mut discard = [0_u8; 1024];
            loop {
                match stdin.read(&mut discard) {
                    Ok(0) | Err(_) => {
                        disconnected.store(true, Ordering::Release);
                        break;
                    }
                    Ok(_) => {}
                }
            }
        });
    }
    while !disconnected.load(Ordering::Acquire) && live_backend(socket)? {
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

fn live_backend(socket: &Path) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "backend socket is not owned by this user",
        ));
    }
    let mut stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let peer = socket_peercred(&stream).map_err(io::Error::from)?;
    if peer.uid != geteuid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "backend process runs as another user",
        ));
    }
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write_json(&mut stream, &Request::List)?;
    match read_json::<Response>(&mut stream)? {
        Some(Response::Secrets { .. }) => Ok(true),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket is live but does not speak the backend protocol",
        )),
    }
}
