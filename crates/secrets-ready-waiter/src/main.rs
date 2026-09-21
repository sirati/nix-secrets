#![forbid(unsafe_code)]

use nix::unistd::{Group, User};
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const SECRET_ROOT: &str = "/persistent/secrets";
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const CATEGORIES: [&str; 3] = ["setup", "service", "backup"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    path: PathBuf,
    owner: String,
    group: String,
    mode: String,
}

#[derive(Debug, Eq, PartialEq)]
struct ExpectedSecret {
    path: PathBuf,
    uid: u32,
    gid: u32,
    mode: u32,
}

fn validate_secret_path(path: &Path) -> Result<(), String> {
    let parts: Vec<_> = path.components().collect();
    let prefix_ok = matches!(parts.first(), Some(Component::RootDir))
        && matches!(parts.get(1), Some(Component::Normal(value)) if *value == "persistent")
        && matches!(parts.get(2), Some(Component::Normal(value)) if *value == "secrets");
    let category_ok = matches!(parts.get(4), Some(Component::Normal(value))
        if CATEGORIES.iter().any(|category| value == category));
    let normal_tail = parts
        .get(3..)
        .is_some_and(|tail| tail.iter().all(|part| matches!(part, Component::Normal(_))));
    if parts.len() != 6 || !prefix_ok || !category_ok || !normal_tail {
        return Err(format!(
            "{} is not /persistent/secrets/<service>/<setup|service|backup>/<secret>",
            path.display()
        ));
    }
    Ok(())
}

fn parse_mode(value: &str) -> Result<u32, String> {
    if value.len() != 4 || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(format!("mode {value:?} must contain four octal digits"));
    }
    u32::from_str_radix(value, 8).map_err(|error| format!("invalid mode {value:?}: {error}"))
}

fn resolve_entry(entry: ManifestEntry) -> Result<ExpectedSecret, String> {
    validate_secret_path(&entry.path)?;
    let uid = User::from_name(&entry.owner)
        .map_err(|error| format!("cannot resolve owner {}: {error}", entry.owner))?
        .ok_or_else(|| format!("unknown owner: {}", entry.owner))?
        .uid
        .as_raw();
    let gid = Group::from_name(&entry.group)
        .map_err(|error| format!("cannot resolve group {}: {error}", entry.group))?
        .ok_or_else(|| format!("unknown group: {}", entry.group))?
        .gid
        .as_raw();
    Ok(ExpectedSecret {
        path: entry.path,
        uid,
        gid,
        mode: parse_mode(&entry.mode)?,
    })
}

fn parse_manifest(contents: &str) -> Result<Vec<ExpectedSecret>, String> {
    let entries: Vec<ManifestEntry> = serde_json::from_str(contents)
        .map_err(|error| format!("invalid JSON manifest: {error}"))?;
    if entries.is_empty() {
        return Err("the manifest contains no secret objects".into());
    }
    let mut paths = HashSet::with_capacity(entries.len());
    let mut resolved = Vec::with_capacity(entries.len());
    for entry in entries {
        if !paths.insert(entry.path.clone()) {
            return Err(format!("duplicate secret path: {}", entry.path.display()));
        }
        resolved.push(resolve_entry(entry)?);
    }
    Ok(resolved)
}

fn is_generation_id(value: &str) -> bool {
    value.split_once('-').is_some_and(|(time, process)| {
        time.len() == 39
            && process.len() == 10
            && time.bytes().all(|byte| byte.is_ascii_digit())
            && process.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn real_directory(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display())),
    }
}

fn current_generation(root: &Path) -> Result<Option<PathBuf>, String> {
    for directory in [
        root.parent().unwrap_or(root),
        root,
        &root.join(".generations"),
    ] {
        if !real_directory(directory)? {
            return Ok(None);
        }
    }
    let current = root.join(".current");
    let metadata = match fs::symlink_metadata(&current) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect {}: {error}", current.display())),
    };
    if !metadata.file_type().is_symlink() {
        return Err(format!("{} is not the required symlink", current.display()));
    }
    let target = fs::read_link(&current)
        .map_err(|error| format!("cannot read {}: {error}", current.display()))?;
    let parts: Vec<_> = target.components().collect();
    let valid = parts.len() == 2
        && parts[0].as_os_str() == ".generations"
        && parts[1].as_os_str().to_str().is_some_and(is_generation_id);
    if !valid {
        return Err(format!("{} has an invalid target", current.display()));
    }
    let generation = root.join(target);
    Ok(real_directory(&generation)?.then_some(generation))
}

fn expected_parts(
    expected: &ExpectedSecret,
) -> (&std::ffi::OsStr, &std::ffi::OsStr, &std::ffi::OsStr) {
    let mut parts = expected.path.components().skip(3);
    let service = parts.next().expect("validated service path").as_os_str();
    let category = parts.next().expect("validated category path").as_os_str();
    let secret = parts.next().expect("validated secret path").as_os_str();
    (service, category, secret)
}

fn secret_is_ready_at(root: &Path, expected: &ExpectedSecret) -> Result<bool, String> {
    let Some(generation) = current_generation(root)? else {
        return Ok(false);
    };
    let (service, category, secret) = expected_parts(expected);
    let service_link = root.join(service);
    let metadata = match fs::symlink_metadata(&service_link) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "cannot inspect {}: {error}",
                service_link.display()
            ));
        }
    };
    let expected_target = Path::new(".current").join(service);
    if !metadata.file_type().is_symlink()
        || fs::read_link(&service_link).map_err(|error| error.to_string())? != expected_target
    {
        return Err(format!(
            "{} is not the required service symlink",
            service_link.display()
        ));
    }
    let service_dir = generation.join(service);
    let category_dir = service_dir.join(category);
    if !real_directory(&service_dir)? || !real_directory(&category_dir)? {
        return Ok(false);
    }
    let path = category_dir.join(secret);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    };
    Ok(metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == expected.uid
        && metadata.gid() == expected.gid
        && metadata.permissions().mode() & 0o7777 == expected.mode)
}

fn run(manifest: &Path) -> Result<(), String> {
    let contents = fs::read_to_string(manifest)
        .map_err(|error| format!("cannot read manifest {}: {error}", manifest.display()))?;
    let secrets = parse_manifest(&contents)?;
    loop {
        if secrets
            .iter()
            .map(|secret| secret_is_ready_at(Path::new(SECRET_ROOT), secret))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .all(|ready| ready)
        {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let manifest = match (args.next(), args.next()) {
        (Some(manifest), None) => manifest,
        _ => {
            eprintln!("usage: {} MANIFEST", Path::new(&program).display());
            return ExitCode::FAILURE;
        }
    };
    match run(Path::new(&manifest)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("secrets-ready-waiter: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
