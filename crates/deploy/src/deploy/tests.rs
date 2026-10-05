use super::*;
use crate::schema::{ResolvedBatch, ResolvedSecret};
use nix::unistd::{getegid, geteuid};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn entry(service: &str, secret: &str, contents: &[u8]) -> ResolvedSecret {
    ResolvedSecret {
        identifier: format!("host.services.{service}.{secret}"),
        version_id: format!("v-{}", contents[0]),
        service: service.into(),
        class: SecretClass::Service,
        secret: secret.into(),
        contents: contents.into(),
        owner: geteuid().as_raw(),
        group: getegid().as_raw(),
        mode: 0o440,
        audit_ssh_user: None,
        audit_key_names: Vec::new(),
    }
}

fn batch(first: &[u8], second: &[u8]) -> ResolvedBatch {
    ResolvedBatch {
        entries: vec![
            entry("mail", "first", first),
            entry("git", "second", second),
        ],
    }
}

#[test]
fn public_info_is_world_readable_at_a_traversable_generation_path() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("public-info");
    let deployer = Deployer::at(&root).unwrap();
    let mut public = entry(
        "storage-box",
        "known-hosts",
        b"[box.example]:23 ssh-ed25519 key\n",
    );
    public.class = SecretClass::PublicInfo;
    public.mode = 0o644;
    deployer
        .deploy(&ResolvedBatch {
            entries: vec![public],
        })
        .unwrap();
    let path = root.join("storage-box/known-hosts");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "[box.example]:23 ssh-ed25519 key\n"
    );
    let resolved = std::fs::canonicalize(&path).unwrap();
    let file = std::fs::metadata(&resolved).unwrap();
    assert_eq!(file.permissions().mode() & 0o777, 0o644);
    for ancestor in resolved.ancestors().take_while(|path| path != &temp.path()) {
        if ancestor.is_dir() {
            assert_ne!(
                std::fs::metadata(ancestor).unwrap().permissions().mode() & 0o001,
                0
            );
        }
    }
}

fn visible_pair(root: &Path) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(root.join("mail/service/first")).unwrap(),
        fs::read(root.join("git/service/second")).unwrap(),
    )
}

#[test]
fn every_publish_crash_exposes_one_whole_generation() {
    let points = [
        FailurePoint::StorePrepared,
        FailurePoint::BaseCopied,
        FailurePoint::SecretStaged(0),
        FailurePoint::SecretStaged(1),
        FailurePoint::VersionsStaged,
        FailurePoint::GenerationSynced,
        FailurePoint::GenerationPublished,
        FailurePoint::ServiceLinksPrepared,
        FailurePoint::PointerPrepared,
        FailurePoint::GenerationAccessible,
        FailurePoint::PointerSwitched,
        FailurePoint::PointerSynced,
    ];
    for point in points {
        let temp = tempfile::tempdir().unwrap();
        let deployer = Deployer::at(temp.path()).unwrap();
        deployer.deploy(&batch(b"old-one", b"old-two")).unwrap();
        assert!(deployer
            .deploy_failing_at(&batch(b"new-one", b"new-two"), point)
            .is_err());
        let visible = visible_pair(temp.path());
        assert!(
            visible == (b"old-one".to_vec(), b"old-two".to_vec())
                || visible == (b"new-one".to_vec(), b"new-two".to_vec()),
            "mixed generation after {point:?}: {visible:?}"
        );
    }
}

#[test]
fn stable_service_links_follow_the_single_current_pointer() {
    let temp = tempfile::tempdir().unwrap();
    let deployer = Deployer::at(temp.path()).unwrap();
    deployer.deploy(&batch(b"one", b"two")).unwrap();
    assert_eq!(
        fs::read_link(temp.path().join("mail")).unwrap(),
        Path::new(".current/mail")
    );
    assert_eq!(
        fs::read_link(temp.path().join("git")).unwrap(),
        Path::new(".current/git")
    );
    let current = fs::read_link(temp.path().join(".current")).unwrap();
    assert!(current.starts_with(".generations"));
    assert_eq!(
        deployer
            .secret_path("mail", SecretClass::Service, "first")
            .unwrap(),
        temp.path().join("mail/service/first")
    );
    assert_eq!(
        deployer
            .current_versions()
            .unwrap()
            .get("host.services.mail.first")
            .unwrap(),
        "v-111"
    );
}

#[test]
fn metadata_and_history_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let deployer = Deployer::at(temp.path()).unwrap();
    for value in 0..6 {
        deployer.deploy(&batch(&[value], &[value])).unwrap();
    }
    let count = fs::read_dir(temp.path().join(".generations"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|item| {
            item.file_name()
                .to_string_lossy()
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    assert_eq!(count, RETAINED_GENERATIONS);
    assert_eq!(
        fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
        0o711
    );
    assert_eq!(
        fs::metadata(temp.path().join(".generations"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o711
    );
    let secret = fs::metadata(temp.path().join("mail/service/first")).unwrap();
    assert_eq!(secret.permissions().mode() & 0o777, 0o440);
    assert_eq!(secret.uid(), geteuid().as_raw());
    assert_eq!(secret.gid(), getegid().as_raw());
}

#[test]
fn carried_secrets_use_distinct_inodes_from_rollback_generations() {
    let temp = tempfile::tempdir().unwrap();
    let deployer = Deployer::at(temp.path()).unwrap();
    deployer.deploy(&batch(b"old-one", b"old-two")).unwrap();
    let old_generation = temp
        .path()
        .join(fs::read_link(temp.path().join(".current")).unwrap());
    let old_secret = old_generation.join("mail/service/first");
    let only_git = ResolvedBatch {
        entries: vec![entry("git", "second", b"new-two")],
    };
    deployer.deploy(&only_git).unwrap();
    let current_secret = temp.path().join("mail/service/first");
    assert_ne!(
        fs::metadata(&old_secret).unwrap().ino(),
        fs::metadata(&current_secret).unwrap().ino()
    );
    fs::set_permissions(&current_secret, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&current_secret, b"mutated-current").unwrap();
    assert_eq!(fs::read(old_secret).unwrap(), b"old-one");
}

#[test]
fn partial_deploy_preserves_exact_file_and_directory_posix_acls() {
    fn acl(owner: u16, reader: u32, permission: u16, mask: u16) -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, perms, id) in [
            (1u16, owner, u32::MAX),
            (2, permission, reader),
            (4, 0, u32::MAX),
            (16, mask, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(perms.to_le_bytes());
            bytes.extend(id.to_le_bytes());
        }
        bytes
    }
    fn set(path: &Path, name: &str, value: &[u8]) -> Result<(), rustix::io::Errno> {
        let file = File::open(path).unwrap();
        rustix::fs::fsetxattr(&file, name, value, rustix::fs::XattrFlags::empty())
    }
    fn get(path: &Path, name: &str) -> Option<Vec<u8>> {
        let file = File::open(path).unwrap();
        let mut value = vec![0; 65536];
        match rustix::fs::fgetxattr(&file, name, value.as_mut_slice()) {
            Ok(length) => {
                value.truncate(length);
                Some(value)
            }
            Err(rustix::io::Errno::NODATA) => None,
            Err(error) => panic!("cannot read POSIX ACL: {error}"),
        }
    }
    let access = "system.posix_acl_access";
    let default = "system.posix_acl_default";
    // The unpacked build source uses the real filesystem; sandbox /tmp may
    // be tmpfs without POSIX ACL support. TempDir still removes the fixture.
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let deployer = Deployer::at(temp.path()).unwrap();
    deployer.deploy(&batch(b"old-one", b"old-two")).unwrap();
    let old = temp
        .path()
        .join(fs::read_link(temp.path().join(".current")).unwrap());
    let reader = nix::unistd::geteuid().as_raw();
    let file_acl = acl(4, reader, 4, 4);
    let dir_acl = acl(7, reader, 1, 1);
    let default_acl = acl(7, reader, 4, 4);
    match set(&old.join("mail/service/first"), access, &file_acl) {
        Ok(()) => {}
        Err(rustix::io::Errno::NOTSUP) => {
            eprintln!("SKIP actual POSIX ACL preservation proof: test filesystem does not support POSIX ACLs; real fleet Btrfs audit remains mandatory");
            return;
        }
        Err(error) => panic!("cannot establish POSIX ACL fixture: {error}"),
    }
    set(&old.join("mail/service"), access, &dir_acl).unwrap();
    set(&old.join("mail/service"), default, &default_acl).unwrap();
    deployer
        .deploy(&ResolvedBatch {
            entries: vec![entry("git", "second", b"new-two")],
        })
        .unwrap();
    let current_file = temp.path().join("mail/service/first");
    let current_dir = temp.path().join("mail/service");
    assert_eq!(get(&current_file, access), Some(file_acl.clone()));
    assert_eq!(get(&current_dir, access), Some(dir_acl));
    assert_eq!(get(&current_dir, default), Some(default_acl));
    assert_eq!(fs::metadata(&current_file).unwrap().mode() & 0o777, 0o440);
    assert_ne!(
        fs::metadata(&current_file).unwrap().ino(),
        fs::metadata(old.join("mail/service/first")).unwrap().ino()
    );
    assert_eq!(get(&old.join("mail/service/first"), access), Some(file_acl));
    // A changed manifest value does not acquire readers from a carried default ACL.
    deployer
        .deploy(&ResolvedBatch {
            entries: vec![entry("mail", "first", b"new-one")],
        })
        .unwrap();
    assert_eq!(get(&current_file, access), None);
    assert_eq!(fs::read(current_file).unwrap(), b"new-one");
}

#[test]
fn rejects_store_and_namespace_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let actual = temp.path().join("actual");
    fs::create_dir(&actual).unwrap();
    let linked_root = temp.path().join("linked");
    std::os::unix::fs::symlink(&actual, &linked_root).unwrap();
    assert!(Deployer::at(&linked_root)
        .unwrap()
        .deploy(&batch(b"a", b"b"))
        .is_err());

    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    std::os::unix::fs::symlink(".current/other", root.join("mail")).unwrap();
    assert!(Deployer::at(&root)
        .unwrap()
        .deploy(&batch(b"a", b"b"))
        .is_err());

    let root = temp.path().join("root-two");
    fs::create_dir(&root).unwrap();
    std::os::unix::fs::symlink(&actual, root.join(".generations")).unwrap();
    assert!(Deployer::at(&root)
        .unwrap()
        .deploy(&batch(b"a", b"b"))
        .is_err());

    let root = temp.path().join("root-three");
    fs::create_dir(&root).unwrap();
    std::os::unix::fs::symlink(actual.join("lock"), root.join(".deploy-lock")).unwrap();
    assert!(Deployer::at(&root)
        .unwrap()
        .deploy(&batch(b"a", b"b"))
        .is_err());
}

#[test]
fn identical_redeploy_keeps_runtime_reader_acl_until_the_value_changes() {
    // owner r, named reader r, owning group r (spec 0440), mask r, other none.
    fn acl(reader: u32) -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, perms, id) in [
            (1u16, 4u16, u32::MAX),
            (2, 4, reader),
            (4, 4, u32::MAX),
            (16, 4, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(perms.to_le_bytes());
            bytes.extend(id.to_le_bytes());
        }
        bytes
    }
    fn access(path: &Path) -> Option<Vec<u8>> {
        let file = File::open(path).unwrap();
        let mut value = vec![0; 65536];
        match rustix::fs::fgetxattr(&file, "system.posix_acl_access", value.as_mut_slice()) {
            Ok(length) => {
                value.truncate(length);
                Some(value)
            }
            Err(rustix::io::Errno::NODATA) => None,
            Err(error) => panic!("cannot read POSIX ACL: {error}"),
        }
    }
    let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let deployer = Deployer::at(temp.path()).unwrap();
    deployer.deploy(&batch(b"old-one", b"old-two")).unwrap();
    let current = temp.path().join("mail/service/first");
    let reader = acl(nix::unistd::geteuid().as_raw());
    let file = File::open(&current).unwrap();
    match rustix::fs::fsetxattr(
        &file,
        "system.posix_acl_access",
        &reader,
        rustix::fs::XattrFlags::empty(),
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::NOTSUP) => {
            eprintln!(
                "SKIP identical redeploy ACL proof: test filesystem does not support POSIX ACLs"
            );
            return;
        }
        Err(error) => panic!("cannot establish POSIX ACL fixture: {error}"),
    }
    drop(file);
    let before = fs::metadata(&current).unwrap().ino();
    // An update redeploys every value; identical ones keep their readers.
    deployer.deploy(&batch(b"old-one", b"new-two")).unwrap();
    assert_eq!(access(&current), Some(reader.clone()));
    assert_eq!(fs::read(&current).unwrap(), b"old-one");
    assert_ne!(fs::metadata(&current).unwrap().ino(), before);
    // Same bytes under a different mode are a changed value: no inherited readers.
    let mut stricter = entry("mail", "first", b"old-one");
    stricter.mode = 0o400;
    deployer
        .deploy(&ResolvedBatch {
            entries: vec![stricter],
        })
        .unwrap();
    assert_eq!(access(&current), None);
    assert_eq!(fs::metadata(&current).unwrap().mode() & 0o777, 0o400);
    // Changed bytes likewise restage from the manifest.
    let file = File::open(&current).unwrap();
    rustix::fs::fsetxattr(
        &file,
        "system.posix_acl_access",
        &acl(nix::unistd::geteuid().as_raw()),
        rustix::fs::XattrFlags::empty(),
    )
    .ok();
    drop(file);
    deployer.deploy(&batch(b"new-one", b"new-two")).unwrap();
    assert_eq!(access(&current), None);
    assert_eq!(fs::read(&current).unwrap(), b"new-one");
}
