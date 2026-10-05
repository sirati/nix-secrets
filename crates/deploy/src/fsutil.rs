use crate::DeployError;
use nix::unistd::{fchown, Gid, Uid};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read};
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
                let input = open_directory(&entry.path())?;
                let output = open_directory(&target)?;
                copy_owner_and_acls(&input, &output)?;
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
    copy_owner_and_acls(&input, &output)?;
    output.sync_all()?;
    Ok(())
}

fn open_directory(path: &Path) -> Result<File, DeployError> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?)
}

const ACCESS_ACL: &str = "system.posix_acl_access";
const DEFAULT_ACL: &str = "system.posix_acl_default";
const MAX_ACL_BYTES: usize = 65536;

/// Carried secrets retain the exact runtime reader policy on distinct inodes.
/// Copy only POSIX ACLs, never capabilities or unrelated security attributes.
fn copy_owner_and_acls(input: &File, output: &File) -> Result<(), DeployError> {
    let metadata = input.metadata()?;
    fchown(
        output.as_raw_fd(),
        Some(Uid::from_raw(metadata.uid())),
        Some(Gid::from_raw(metadata.gid())),
    )
    .map_err(|error| DeployError::Io(io::Error::from_raw_os_error(error as i32)))?;
    output.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
    for name in [ACCESS_ACL, DEFAULT_ACL] {
        let mut value = vec![0u8; MAX_ACL_BYTES];
        let length = match rustix::fs::fgetxattr(input, name, value.as_mut_slice()) {
            Ok(length) => length,
            Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP) => {
                remove_acl(output, name)?;
                continue;
            }
            Err(error) => return Err(io::Error::from(error).into()),
        };
        value.truncate(length);
        rustix::fs::fsetxattr(output, name, &value, rustix::fs::XattrFlags::empty())
            .map_err(io::Error::from)?;
    }
    if output.metadata()?.mode() & 0o7777 != metadata.mode() & 0o7777 {
        return Err(DeployError::Invalid(
            "copied POSIX ACL mode differs from source".into(),
        ));
    }
    output.sync_all()?;
    Ok(())
}

fn remove_acl(file: &File, name: &str) -> Result<(), DeployError> {
    match rustix::fs::fremovexattr(file, name) {
        // An unsupported ACL namespace cannot contain an inherited ACL.
        Ok(()) | Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP) => Ok(()),
        Err(error) => Err(io::Error::from(error).into()),
    }
}

/// Changed values start from the manifest, not inherited directory readers.
pub(crate) fn clear_access_acl(file: &File) -> Result<(), DeployError> {
    remove_acl(file, ACCESS_ACL)
}

/// A redeployed value whose bytes, owner, group and permissions already match
/// the carried file keeps that file and its exact runtime reader ACL. Every
/// update redeploys all values; restaging identical values without their
/// readers broke services started during activation.
pub(crate) fn unchanged_carried(
    path: &Path,
    contents: &[u8],
    owner: u32,
    group: u32,
    mode: u32,
) -> Result<bool, DeployError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        // Absent or not a plain file: staging decides how to handle it.
        Err(_) => return Ok(false),
    };
    let metadata = file.metadata()?;
    let actual = metadata.mode() & 0o7777;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.gid() != group
        || metadata.len() != contents.len() as u64
        || actual & !0o070 != mode & !0o070
    {
        return Ok(false);
    }
    // With an access ACL the group bits show its mask; the owning group's
    // permission is then the ACL group-object entry.
    let group_permission = match group_object(&file)? {
        Some(permission) => u32::from(permission),
        None => (actual >> 3) & 0o7,
    };
    if group_permission != (mode >> 3) & 0o7 {
        return Ok(false);
    }
    let mut existing = Vec::with_capacity(contents.len());
    (&file)
        .take(contents.len() as u64 + 1)
        .read_to_end(&mut existing)?;
    Ok(existing == contents)
}

fn group_object(file: &File) -> Result<Option<u16>, DeployError> {
    let mut value = vec![0u8; MAX_ACL_BYTES];
    let length = match rustix::fs::fgetxattr(file, ACCESS_ACL, value.as_mut_slice()) {
        Ok(length) => length,
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP) => return Ok(None),
        Err(error) => return Err(io::Error::from(error).into()),
    };
    let value = &value[..length];
    if value.len() < 4 || (value.len() - 4) % 8 != 0 || value[..4] != 2u32.to_le_bytes() {
        return Err(DeployError::Invalid(
            "carried secret has an invalid POSIX ACL".into(),
        ));
    }
    let entry = value[4..]
        .chunks_exact(8)
        .find(|entry| u16::from_le_bytes([entry[0], entry[1]]) == 4)
        .ok_or_else(|| DeployError::Invalid("carried secret ACL has no group entry".into()))?;
    Ok(Some(u16::from_le_bytes([entry[2], entry[3]])))
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
