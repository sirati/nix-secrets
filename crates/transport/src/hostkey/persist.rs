//! Persist only keys explicitly approved for the exact SSH endpoint.
use super::*;
use std::io::{Read, Write};
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

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
        return Err(refusal("known_hosts must be a bounded, owned regular file without writable group or other access"));
    }
    Ok(())
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
            return Err(refusal("known_hosts parent must be an owned directory without symlinks or untrusted writes"));
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
        rustix::fs::flock(&target, rustix::fs::FlockOperation::NonBlockingLockExclusive)
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
                    return Err(refusal("host has a revoked or certificate-authority entry; refusing to alter trust"));
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
            let path = std::env::temp_dir().join(format!(
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
        fn run(&self, program:&OsStr, arguments:&[OsString])->Result<runner::Output,HostKeyError> {
            if program==OsStr::new("ssh-keyscan") {Ok(runner::Output{success:true,stdout:b"[ns1.example]:2222 ssh-ed25519 AAAA\n".to_vec(),diagnostic:String::new()})}
            else {ProcessRunner.run(program,arguments)}
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
        assert_eq!(verifier.preflight_with("ns1.example",2222,&ScanKnown).unwrap().status,HostKeyStatus::Known);

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
        assert!(Command::new("ssh-keygen")
            .args(["-H", "-f"])
            .arg(&path)
            .output()
            .unwrap()
            .status
            .success());
        let before = fs::read(&path).unwrap();
        assert!(HostKeyVerifier::new(vec![path.clone()])
            .persist_accepted(&identity())
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}
