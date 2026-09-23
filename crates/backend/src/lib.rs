#![forbid(unsafe_code)]

mod cli;
mod manifest;
mod socket_lease;

pub use cli::{Arguments, ParseError};
pub use manifest::{evaluate_manifest, load_manifest, MAX_MANIFEST_BYTES};

use nix_secrets_core::{Backend, Schema, SecretStore};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

pub fn run(arguments: Arguments) -> Result<(), Box<dyn Error>> {
    let repository = canonical_repository(&arguments.repository)?;
    let lease = match socket_lease::acquire_or_attach(&arguments.socket)? {
        socket_lease::Disposition::Owner(lease) => lease,
        socket_lease::Disposition::Attached => {
            socket_lease::watch_existing(&arguments.socket, arguments.hold_channel)?;
            return Ok(());
        }
    };
    let input = match &arguments.manifest {
        Some(path) => load_manifest(path)?,
        None => evaluate_manifest(&repository)?,
    };
    let schema = Schema::from_json(&input)?;
    reject_non_file_store(&repository.join("nix-secrets.toml"))?;
    let store = SecretStore::new(repository.join("nix-secrets.toml"));
    let backend = Backend::bind(arguments.socket, schema, store)?;
    // Keep the lock for the entire lifetime of this backend. A second launch
    // attaches to this socket instead of replacing its approval broker.
    let _lease = lease;

    // Binding is the readiness boundary: the private socket exists only after
    // the repository and freshly evaluated schema have passed validation.
    backend.serve()?;
    Ok(())
}

fn canonical_repository(path: &Path) -> io::Result<PathBuf> {
    let bytes = path.as_os_str().as_bytes();
    let expanded = if bytes == b"~" {
        PathBuf::from(
            env::var_os("HOME")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "HOME is not set"))?,
        )
    } else if let Some(rest) = bytes.strip_prefix(b"~/") {
        let mut home = PathBuf::from(
            env::var_os("HOME")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "HOME is not set"))?,
        );
        home.push(std::ffi::OsString::from_vec(rest.to_vec()));
        home
    } else if bytes.first() == Some(&b'~') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only ~ and ~/ repository paths are supported",
        ));
    } else {
        path.to_path_buf()
    };
    let path = fs::canonicalize(expanded)?;
    if !fs::metadata(&path)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "repository is not a directory",
        ));
    }
    Ok(path)
}

fn reject_non_file_store(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nix-secrets.toml is not a regular file",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_named_user_tilde_without_shell_expansion() {
        let error = canonical_repository(Path::new("~some-user/repo")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
