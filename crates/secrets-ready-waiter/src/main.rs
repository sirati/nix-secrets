#![forbid(unsafe_code)]

mod notify;
mod progress;
mod report;

use nix::unistd::{Group, User};
use progress::Progress;
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

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
    #[serde(default)]
    runtime_readers: Vec<RuntimeReader>,
    #[serde(default)]
    acl_program: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeReader {
    account: String,
    uid_offset: u32,
}

#[derive(Debug, Eq, PartialEq)]
struct ExpectedSecret {
    path: PathBuf,
    uid: u32,
    gid: u32,
    mode: u32,
    runtime_uids: Vec<u32>,
    acl_program: Option<PathBuf>,
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

fn resolve_runtime_uid(contents: &str, reader: &RuntimeReader) -> Result<u32, String> {
    let mut matches = contents.lines().filter_map(|line| {
        let fields: Vec<_> = line.split(':').collect();
        (fields.first().copied() == Some(reader.account.as_str())).then_some(fields)
    });
    let fields = matches
        .next()
        .ok_or("runtime reader has no subordinate UID range")?;
    if fields.len() != 3 || matches.next().is_some() {
        return Err("runtime reader subordinate UID range is ambiguous".into());
    }
    let start: u32 = fields[1].parse().map_err(|_| "invalid runtime UID start")?;
    let count: u32 = fields[2].parse().map_err(|_| "invalid runtime UID count")?;
    let uid = start
        .checked_add(reader.uid_offset)
        .ok_or("runtime UID overflow")?;
    if start == 0 || reader.uid_offset >= count || uid == u32::MAX {
        return Err("runtime UID outside declared range".into());
    }
    Ok(uid)
}

fn exact_runtime_acl(text: &str, uids: &[u32]) -> bool {
    let mut actual: Vec<_> = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    let mut expected = vec![
        "user::r--".into(),
        "group::---".into(),
        "mask::r--".into(),
        "other::---".into(),
    ];
    expected.extend(uids.iter().map(|uid| format!("user:{uid}:r--")));
    actual.sort();
    expected.sort();
    actual == expected
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
    let mode = parse_mode(&entry.mode)?;
    let mut runtime_uids = Vec::new();
    if !entry.runtime_readers.is_empty() {
        if uid != 0 || gid != 0 || mode != 0o400 {
            return Err("runtime reader policy requires root-owned 0400 deployment".into());
        }
        let program = entry
            .acl_program
            .as_ref()
            .ok_or("runtime ACL checker missing")?;
        if !program.starts_with("/nix/store")
            || program.file_name().is_none_or(|name| name != "getfacl")
            || program
                .parent()
                .and_then(Path::file_name)
                .is_none_or(|name| name != "bin")
            || program
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err("runtime ACL checker must be immutable getfacl".into());
        }
        let contents = fs::read_to_string("/etc/subuid")
            .map_err(|error| format!("reading runtime UID mappings: {error}"))?;
        for reader in &entry.runtime_readers {
            let mapped = resolve_runtime_uid(&contents, reader)?;
            if runtime_uids.contains(&mapped) {
                return Err("duplicate runtime reader UID".into());
            }
            runtime_uids.push(mapped);
        }
    }
    Ok(ExpectedSecret {
        path: entry.path,
        uid,
        gid,
        mode,
        runtime_uids,
        acl_program: entry.acl_program,
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
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected.uid
        || metadata.gid() != expected.gid
    {
        return Ok(false);
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode == expected.mode {
        return Ok(true);
    }
    if mode != 0o440 || expected.runtime_uids.is_empty() {
        return Ok(false);
    }
    let output = std::process::Command::new(
        expected
            .acl_program
            .as_ref()
            .ok_or("runtime ACL checker missing")?,
    )
    .args(["-cpn", "--"])
    .arg(&path)
    .output()
    .map_err(|error| format!("inspecting runtime ACL: {error}"))?;
    if !output.status.success() || output.stdout.len() > 65536 {
        return Err("runtime ACL inspection failed".into());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| "runtime ACL is not UTF-8")?;
    Ok(exact_runtime_acl(text, &expected.runtime_uids))
}

fn missing_secrets(root: &Path, secrets: &[ExpectedSecret]) -> Result<Vec<PathBuf>, String> {
    let mut missing = Vec::new();
    for secret in secrets {
        if !secret_is_ready_at(root, secret)? {
            missing.push(secret.path.clone());
        }
    }
    Ok(missing)
}

/// Best effort: a status that cannot be published never fails the waiter.
fn publish_status(socket: Option<&OsStr>, text: &str, failed: &mut bool) {
    if let Err(error) = notify::send(socket, &notify::status_message(text))
        && !std::mem::replace(failed, true)
    {
        eprintln!("secrets-ready-waiter: cannot update the unit status: {error}");
    }
}

fn run(manifest: &Path, once: bool) -> Result<(), String> {
    let contents = fs::read_to_string(manifest)
        .map_err(|error| format!("cannot read manifest {}: {error}", manifest.display()))?;
    let secrets = parse_manifest(&contents)?;
    let socket = env::var_os("NOTIFY_SOCKET");
    let started = Instant::now();
    let mut progress = Progress::default();
    let mut notify_failed = false;
    loop {
        let emit = match poll(Path::new(SECRET_ROOT), &secrets, &mut progress, started.elapsed()) {
            Poll::Ready => {
                if progress.waited() {
                    publish_status(
                        socket.as_deref(),
                        "declared secrets are ready",
                        &mut notify_failed,
                    );
                }
                return Ok(());
            }
            Poll::Waiting(emit) if once => {
                let reason = emit.status.unwrap_or_default();
                return Err(format!("declared secrets are not ready: {reason}"));
            }
            Poll::Waiting(emit) => emit,
        };
        if let Some(status) = emit.status {
            publish_status(socket.as_deref(), &status, &mut notify_failed);
        }
        if let Some(line) = emit.log {
            eprintln!("{line}");
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Poll {
    Ready,
    /// Not ready, with what to publish about it.
    Waiting(progress::Emit),
}

/// One look at `root`. Only every declared secret in place is ready. A
/// secret that cannot be inspected is not ready either: the waiter keeps
/// waiting with the reason in its status, so its consumers stay blocked
/// and the long-wait report names the reason, until a deployment or the
/// operator repairs it.
fn poll(
    root: &Path,
    secrets: &[ExpectedSecret],
    progress: &mut Progress,
    elapsed: Duration,
) -> Poll {
    match missing_secrets(root, secrets) {
        Ok(missing) if missing.is_empty() => Poll::Ready,
        Ok(missing) => Poll::Waiting(progress.observe(&missing, elapsed)),
        Err(error) => Poll::Waiting(progress.observe_error(&error, elapsed)),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Mode {
    Wait { manifest: PathBuf, once: bool },
    Report { systemctl: PathBuf, after: Duration },
}

fn parse_report_args(args: &[OsString]) -> Result<Mode, String> {
    let (mut systemctl, mut after) = (None, None);
    for pair in args.chunks(2) {
        let [flag, value] = pair else {
            return Err("missing option value".into());
        };
        let slot = if flag == "--systemctl" {
            &mut systemctl
        } else if flag == "--after" {
            &mut after
        } else {
            return Err(format!("unknown option {}", flag.to_string_lossy()));
        };
        if slot.replace(value.clone()).is_some() {
            return Err(format!("duplicate option {}", flag.to_string_lossy()));
        }
    }
    let systemctl = PathBuf::from(systemctl.ok_or("--systemctl is required")?);
    if !systemctl.is_absolute() {
        return Err("--systemctl must be an absolute path".into());
    }
    let after = after
        .ok_or("--after is required")?
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or("--after must be a whole number of seconds")?;
    Ok(Mode::Report {
        systemctl,
        after: Duration::from_secs(after),
    })
}

fn parse_args(args: &[OsString]) -> Result<Mode, String> {
    match args {
        [mode, rest @ ..] if mode == "--report-waiting" => parse_report_args(rest),
        [manifest] => Ok(Mode::Wait {
            manifest: manifest.into(),
            once: false,
        }),
        [manifest, flag] if flag == "--once" => Ok(Mode::Wait {
            manifest: manifest.into(),
            once: true,
        }),
        _ => Err("invalid arguments".into()),
    }
}

fn report_exit(result: Result<u8, String>) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("secrets-ready-waiter: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let args: Vec<_> = args.collect();
    match parse_args(&args) {
        Ok(Mode::Wait { manifest, once }) => report_exit(run(&manifest, once).map(|()| 0)),
        Ok(Mode::Report { systemctl, after }) => report_exit(report::run(&systemctl, after)),
        Err(error) => {
            let program = Path::new(&program).display().to_string();
            eprintln!(
                "secrets-ready-waiter: {error}\nusage: {program} MANIFEST [--once]\n       {program} --report-waiting --systemctl ABSOLUTE_PATH --after SECONDS"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
