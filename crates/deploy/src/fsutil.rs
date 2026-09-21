use crate::DeployError;
use nix::unistd::{fchown, Gid, Uid};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn create_directory(path: &Path, mode: u32) -> Result<(), DeployError> {
    let mut builder = DirBuilder::new();
    builder.mode(mode);
    builder.create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    File::open(path)?.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub(crate) fn clone_tree(source: &Path, destination: &Path) -> Result<(), DeployError> {
    let mut directories = vec![(source.to_path_buf(), destination.to_path_buf())];
    let mut index = 0;
    while index < directories.len() {
        let (from, to) = directories[index].clone();
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            if entry.file_name() == ".versions.json" {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            let target = to.join(entry.file_name());
            if metadata.file_type().is_symlink() {
                return Err(DeployError::Invalid(
                    "symbolic link in current generation".into(),
                ));
            } else if metadata.is_dir() {
                create_directory(&target, metadata.permissions().mode() & 0o777)?;
                directories.push((entry.path(), target));
            } else if metadata.is_file() {
                copy_file(&entry.path(), &target)?;
            } else {
                return Err(DeployError::Invalid(
                    "non-file in current generation".into(),
                ));
            }
        }
        index += 1;
    }
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<(), DeployError> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(source)?;
    let source_metadata = input.metadata()?;
    if !source_metadata.is_file() {
        return Err(DeployError::Invalid(
            "source secret is not a regular file".into(),
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    fchown(
        output.as_raw_fd(),
        Some(Uid::from_raw(source_metadata.uid())),
        Some(Gid::from_raw(source_metadata.gid())),
    )
    .map_err(|error| DeployError::Io(io::Error::from_raw_os_error(error as i32)))?;
    output.set_permissions(fs::Permissions::from_mode(source_metadata.mode() & 0o7777))?;
    output.sync_all()?;
    Ok(())
}

pub(crate) fn sync_tree(root: &Path) -> Result<(), DeployError> {
    let mut directories = vec![root.to_path_buf()];
    let mut index = 0;
    while index < directories.len() {
        for entry in fs::read_dir(&directories[index])? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(DeployError::Invalid(
                    "symbolic link in staged generation".into(),
                ));
            }
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if !metadata.is_file() {
                return Err(DeployError::Invalid("non-file in staged generation".into()));
            }
        }
        index += 1;
    }
    for directory in directories.iter().rev() {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

pub(crate) fn require_real_directory(path: &Path, label: &str) -> Result<(), DeployError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(DeployError::Invalid(format!(
            "{label} is not a real directory"
        )))
    }
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), DeployError> {
    File::open(path)?.sync_all().map_err(DeployError::Io)
}

pub(crate) fn valid_generation(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|value| value.split_once('-'))
        .is_some_and(|(time, process)| {
            time.len() == 39
                && process.len() == 10
                && time.bytes().all(|b| b.is_ascii_digit())
                && process.bytes().all(|b| b.is_ascii_digit())
        })
}

pub(crate) fn generation_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:039}-{:010}", std::process::id())
}
