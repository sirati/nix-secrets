//! Persist only keys explicitly approved for the exact SSH endpoint.
use super::*;
use std::io::{Read, Write};
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};
use std::path::Path;

const LIMIT: u64 = 4 * 1024 * 1024;
fn refusal(message: &str) -> HostKeyError {
    HostKeyError::Tool(format!("cannot save accepted SSH host key: {message}"))
}
fn safe_file(file: &fs::File, owner: u32) -> Result<(), HostKeyError> {
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != owner
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || meta.len() > LIMIT
    {
        return Err(refusal(
            "known_hosts must be a bounded, owned regular file without writable group or other access",
        ));
    }
    Ok(())
}
/// Resolve a managed read-only file without trusting user-owned symlinks.
/// O_PATH pins each directory/link; readlinkat on the link descriptor itself
/// avoids a pathname race while NixOS switches /etc/static generations.
fn managed_secondary(path: &Path) -> Result<fs::File, HostKeyError> {
    use rustix::fs::{Mode, OFlags, openat};
    let root = fs::File::from(
        openat(
            rustix::fs::CWD,
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    managed_secondary_at(&root, path, 0)
}
/// The supplied descriptor is the filesystem namespace root. Production
/// always supplies '/' and uid0. Tests use the immutable fixture namespace's
/// mapped owner because Nix sandboxes expose root-owned dependencies as nobody.
fn managed_secondary_at(
    root: &fs::File,
    path: &Path,
    expected_owner: u32,
) -> Result<fs::File, HostKeyError> {
    use rustix::fs::{Mode, OFlags, openat, readlinkat};
    use std::collections::VecDeque;
    use std::os::unix::ffi::OsStringExt;
    use std::path::Component;
    if !path.is_absolute() {
        return Err(refusal("managed known_hosts must be absolute"));
    }
    let mut directories = vec![root.try_clone()?];
    let components = |value: &Path| -> VecDeque<std::ffi::OsString> {
        value
            .components()
            .filter_map(|component| match component {
                Component::RootDir => None,
                Component::CurDir => Some(".".into()),
                Component::ParentDir => Some("..".into()),
                Component::Normal(name) => Some(name.to_owned()),
                Component::Prefix(_) => Some("..".into()),
            })
            .collect()
    };
    let mut pending = components(path);
    let mut links = 0;
    let mut steps = 0;
    while let Some(name) = pending.pop_front() {
        steps += 1;
        if steps > 256 {
            return Err(refusal("managed known_hosts traversal exceeded limit"));
        }
        if name == "." {
            continue;
        }
        if name == ".." {
            if directories.len() == 1 {
                return Err(refusal("managed known_hosts traverses above root"));
            }
            directories.pop();
            continue;
        }
        let parent = directories.last().unwrap();
        let meta = parent.metadata()?;
        if !meta.is_dir()
            || meta.uid() != expected_owner
            || (meta.mode() & 0o022 != 0
                && !(meta.uid() == expected_owner && meta.mode() & 0o1000 != 0))
        {
            return Err(refusal(&format!(
                "unsafe managed known_hosts ancestor (uid={}, mode={:o}, managed uid={})",
                meta.uid(),
                meta.mode() & 0o7777,
                expected_owner
            )));
        }
        let pinned = fs::File::from(
            openat(
                parent,
                &name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        let meta = pinned.metadata()?;
        if meta.uid() != expected_owner {
            return Err(refusal("managed known_hosts entry is not root-owned"));
        }
        if meta.file_type().is_symlink() {
            links += 1;
            if links > 40 {
                return Err(refusal("managed known_hosts has too many symlinks"));
            }
            let target = readlinkat(&pinned, "", Vec::new()).map_err(io::Error::from)?;
            let target = PathBuf::from(std::ffi::OsString::from_vec(target.into_bytes()));
            if target.is_absolute() {
                directories.truncate(1);
            }
            let mut next = components(&target);
            next.append(&mut pending);
            pending = next;
        } else if pending.is_empty() {
            if !meta.is_file() || meta.mode() & 0o022 != 0 || meta.len() > LIMIT {
                return Err(refusal("unsafe managed known_hosts file"));
            }
            let file = fs::File::open(format!(
                "/proc/{}/fd/{}",
                std::process::id(),
                pinned.as_raw_fd()
            ))?;
            let opened = file.metadata()?;
            if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
                return Err(refusal("managed known_hosts file changed"));
            }
            return Ok(file);
        } else {
            if !meta.is_dir() {
                return Err(refusal("managed known_hosts ancestor is not a directory"));
            }
            directories.push(pinned);
        }
    }
    Err(refusal("managed known_hosts does not name a file"))
}
impl HostKeyVerifier {
    /// Save an explicitly accepted identity. Existing different keys are never
    /// removed or replaced. Errors prevent the requested connection/deployment.
    pub fn persist_accepted(&self, identity: &HostIdentity) -> Result<(), HostKeyError> {
        let path = self
            .known_hosts
            .first()
            .ok_or_else(|| refusal("no client known_hosts file is configured"))?;
        let parent = path
            .parent()
            .ok_or_else(|| refusal("known_hosts has no parent"))?;
        if !path.is_absolute()
            || parent.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(refusal(
                "known_hosts path must be absolute without traversal",
            ));
        }
        let uid = rustix::process::geteuid().as_raw();
        match fs::create_dir(parent) {
            Ok(()) => fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.uid() != uid
            || metadata.mode() & 0o022 != 0
            || parent.canonicalize()? != parent
        {
            return Err(refusal(
                "known_hosts parent must be an owned directory without symlinks or untrusted writes",
            ));
        }
        // Lock the exact no-follow file. Atomic replacement by another writer
        // is detected before publication; callers never overwrite their data.
        let parent_fd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY).bits() as i32,
            )
            .open(parent)?;
        let parent_metadata = parent_fd.metadata()?;
        if (parent_metadata.dev(), parent_metadata.ino()) != (metadata.dev(), metadata.ino()) {
            return Err(refusal("known_hosts parent changed"));
        }
        let mut target = fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(format!(
                "/proc/{}/fd/{}/{}",
                std::process::id(),
                parent_fd.as_raw_fd(),
                path.file_name()
                    .ok_or_else(|| refusal("known_hosts filename absent"))?
                    .to_str()
                    .ok_or_else(|| refusal("known_hosts filename is not UTF-8"))?
            ))?;
        rustix::fs::flock(
            &target,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|e| refusal(&e.to_string()))?;
        safe_file(&target, uid)?;
        if identity.keys.is_empty()
            || identity.host.is_empty()
            || identity.host.bytes().any(|b| {
                b.is_ascii_whitespace()
                    || b == 0
                    || b == b','
                    || b == b'*'
                    || b == b'?'
                    || b == b'!'
                    || b == b'|'
            })
        {
            return Err(refusal("invalid approved host identity"));
        }
        for key in &identity.keys {
            if !matches!(
                key.algorithm.as_str(),
                "ssh-ed25519"
                    | "ssh-rsa"
                    | "ecdsa-sha2-nistp256"
                    | "ecdsa-sha2-nistp384"
                    | "ecdsa-sha2-nistp521"
                    | "sk-ssh-ed25519@openssh.com"
                    | "sk-ecdsa-sha2-nistp256@openssh.com"
                    | "ssh-mldsa-44"
            ) || key.encoded.is_empty()
                || key
                    .encoded
                    .bytes()
                    .any(|b| !(b.is_ascii_alphanumeric() || b"+/=".contains(&b)))
            {
                return Err(refusal("invalid approved public key"));
            }
        }
        let lookup = lookup_name(&identity.host, identity.port);
        let mut recorded = Vec::new();
        for configured in &self.known_hosts {
            let file = if configured == path {
                target.try_clone()?
            } else {
                match fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                    .open(configured)
                {
                    Ok(file) => file,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
                        managed_secondary(configured)?
                    }
                    Err(e) => return Err(e.into()),
                }
            };
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.len() > LIMIT
                || meta.mode() & 0o022 != 0
                || ![0, uid].contains(&meta.uid())
            {
                return Err(refusal("unsafe configured known_hosts file"));
            }
            let pinned = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
            let output = ProcessRunner.run(
                &self.ssh_keygen,
                &[
                    "-F".into(),
                    lookup.clone().into(),
                    "-f".into(),
                    pinned.into(),
                ],
            )?;
            if output.success {
                let text = std::str::from_utf8(&output.stdout)
                    .map_err(|_| refusal("known_hosts output is not UTF-8"))?;
                if text.lines().any(|line| line.starts_with('@')) {
                    return Err(refusal(
                        "host has a revoked or certificate-authority entry; refusing to alter trust",
                    ));
                }
                let lines = parse_key_lines(&output.stdout);
                if lines.is_empty() {
                    return Err(refusal("matching known_hosts entry could not be validated"));
                }
                for line in lines {
                    if !identity
                        .keys
                        .iter()
                        .any(|key| key.algorithm == line.algorithm && key.encoded == line.encoded)
                    {
                        return Err(refusal(
                            "a different host key is already recorded; refusing to replace it",
                        ));
                    }
                    recorded.push(line.presented());
                }
            } else if output.diagnostic != "exit status: 1" {
                return Err(refusal("cannot inspect existing host trust"));
            }
        }
        let mut addition = String::new();
        let mut original = String::new();
        Read::by_ref(&mut target)
            .take(LIMIT + 1)
            .read_to_string(&mut original)
            .map_err(|_| refusal("known_hosts is not bounded UTF-8"))?;
        if original.len() as u64 > LIMIT {
            return Err(refusal("known_hosts exceeds size limit"));
        }
        for key in &identity.keys {
            if !recorded.contains(key) {
                addition.push_str(&format!("{lookup} {} {}\n", key.algorithm, key.encoded));
            }
        }
        if addition.is_empty() {
            return Ok(());
        }
        if !original.is_empty() && !original.ends_with('\n') {
            addition.insert(0, '\n');
        }
        if original.len() + addition.len() > LIMIT as usize {
            return Err(refusal("known_hosts exceeds size limit"));
        }
        let parent_now = fs::symlink_metadata(parent)?;
        if (parent_now.dev(), parent_now.ino()) != (parent_metadata.dev(), parent_metadata.ino()) {
            return Err(refusal("known_hosts parent changed while saving trust"));
        }
        let now = fs::symlink_metadata(path)?;
        let pinned = target.metadata()?;
        if (now.dev(), now.ino()) != (pinned.dev(), pinned.ino()) {
            return Err(refusal("known_hosts changed while saving trust"));
        }
        target.write_all(addition.as_bytes())?;
        target.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            Self::under(&std::env::temp_dir())
        }
        fn under(parent: &Path) -> Self {
            let path = parent.join(format!(
                "nix-secrets-host-trust-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn identity() -> HostIdentity {
        HostIdentity {
            host: "ns1.example".into(),
            port: 2222,
            keys: vec![PresentedKey {
                algorithm: "ssh-ed25519".into(),
                encoded: "AAAA".into(),
            }],
            other_names_with_keys: vec![],
        }
    }
    struct ScanKnown;
    impl Runner for ScanKnown {
        fn run(
            &self,
            program: &OsStr,
            arguments: &[OsString],
        ) -> Result<runner::Output, HostKeyError> {
            if program == OsStr::new("ssh-keyscan") {
                Ok(runner::Output {
                    success: true,
                    stdout: b"[ns1.example]:2222 ssh-ed25519 AAAA\n".to_vec(),
                    diagnostic: String::new(),
                })
            } else {
                ProcessRunner.run(program, arguments)
            }
        }
    }
    #[test]
    fn explicit_trust_persists_exact_endpoint_once_and_refuses_replacement() {
        let fixture = Fixture::new();
        let path = fixture.0.join("known_hosts");
        let verifier = HostKeyVerifier::new(vec![path.clone()]);
        let approved = identity();
        verifier.persist_accepted(&approved).unwrap();
        let original = fs::read(&path).unwrap();
        assert_eq!(
            verifier
                .preflight_with("ns1.example", 2222, &ScanKnown)
                .unwrap()
                .status,
            HostKeyStatus::Known
        );

        assert_eq!(original, b"[ns1.example]:2222 ssh-ed25519 AAAA\n");
        verifier.persist_accepted(&approved).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original);
        let mut changed = approved.clone();
        changed.keys[0].encoded = "BBBB".into();
        assert!(verifier.persist_accepted(&changed).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    #[test]
    fn persistence_errors_refuse_symlinks_untrusted_permissions_and_existing_conflicts() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let path = fixture.0.join("known_hosts");
        let other = fixture.0.join("other");
        fs::write(&other, b"original unrelated data\n").unwrap();
        symlink(&other, &path).unwrap();
        let verifier = HostKeyVerifier::new(vec![path.clone()]);
        assert!(verifier.persist_accepted(&identity()).is_err());
        assert_eq!(fs::read(&other).unwrap(), b"original unrelated data\n");
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"[ns1.example]:2222 ssh-ed25519 BBBB\n").unwrap();
        let before = fs::read(&path).unwrap();
        assert!(verifier.persist_accepted(&identity()).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(verifier.persist_accepted(&identity()).is_err());
    }
    #[test]
    fn hashed_known_host_conflict_is_never_overridden() {
        let fixture = Fixture::new();
        let path = fixture.0.join("known_hosts");
        fs::write(&path, b"[ns1.example]:2222 ssh-ed25519 BBBB\n").unwrap();
        assert!(
            Command::new("ssh-keygen")
                .args(["-H", "-f"])
                .arg(&path)
                .output()
                .unwrap()
                .status
                .success()
        );
        let before = fs::read(&path).unwrap();
        assert!(
            HostKeyVerifier::new(vec![path.clone()])
                .persist_accepted(&identity())
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    fn managed_fixture() -> PathBuf {
        PathBuf::from(
            std::env::var_os("NIX_SECRETS_MANAGED_KNOWN_HOSTS_FIXTURE").expect(
                "run the normal Nix package check to provide the public root-owned fixture",
            ),
        )
    }

    #[test]
    fn nixos_managed_secondary_namespace_pins_root_owned_immutable_file() {
        let root = fs::File::open(managed_fixture()).unwrap();
        let mapped_owner = root.metadata().unwrap().uid();
        let mut content =
            managed_secondary_at(&root, Path::new("/etc/ssh/ssh_known_hosts"), mapped_owner)
                .unwrap();
        assert_eq!(content.metadata().unwrap().uid(), mapped_owner);
        assert!(content.metadata().unwrap().nlink() >= 2);
        let mut bytes = Vec::new();
        content.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes,b"[ns1.example]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n");
        // ssh-keygen inspects the exact pinned file as in persistence, not a
        // pathname that could resolve through a different namespace ancestry.
        let output = ProcessRunner
            .run(
                OsStr::new("ssh-keygen"),
                &[
                    "-F".into(),
                    "[ns1.example]:2222".into(),
                    "-f".into(),
                    format!("/proc/{}/fd/{}", std::process::id(), content.as_raw_fd()).into(),
                ],
            )
            .unwrap();
        assert!(output.success);
        assert_eq!(parse_key_lines(&output.stdout).len(), 1);
    }
    #[test]
    fn managed_secondary_namespace_refuses_user_root_escape_and_root_owned_loop() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let root = fs::File::open(managed_fixture()).unwrap();
        let mapped_owner = root.metadata().unwrap().uid();
        let link = fixture.0.join("user-link");
        symlink(managed_fixture().join("etc/ssh/ssh_known_hosts"), &link).unwrap();
        let untrusted_root = fs::File::open(&fixture.0).unwrap();
        if rustix::process::geteuid().as_raw() != mapped_owner {
            let error =
                managed_secondary_at(&untrusted_root, Path::new("/user-link"), mapped_owner)
                    .unwrap_err()
                    .to_string();
            assert!(error.contains("unsafe managed known_hosts ancestor"));
        }
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            managed_secondary_at(&untrusted_root, Path::new("/user-link"), mapped_owner).is_err()
        );
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            managed_secondary_at(
                &root,
                Path::new("/../etc/ssh/ssh_known_hosts"),
                mapped_owner
            )
            .unwrap_err()
            .to_string()
            .contains("above root")
        );
        assert!(
            managed_secondary_at(&root, Path::new("/loop"), mapped_owner)
                .unwrap_err()
                .to_string()
                .contains("too many symlinks")
        );
    }
}
