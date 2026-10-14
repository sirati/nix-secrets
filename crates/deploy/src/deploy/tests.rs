use super::recovery::{together_failing_at, Root};
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

struct Pair {
    temp: tempfile::TempDir,
    secrets: Deployer,
    public: Deployer,
}

impl Pair {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let secrets = Deployer::at(temp.path().join("secrets")).unwrap();
        let public = Deployer::at(temp.path().join("public-info"))
            .unwrap()
            .committed_with(&secrets);
        Self {
            temp,
            secrets,
            public,
        }
    }

    fn secrets_root(&self) -> PathBuf {
        self.temp.path().join("secrets")
    }

    fn public_root(&self) -> PathBuf {
        self.temp.path().join("public-info")
    }

    fn deploy(&self, value: &[u8]) -> Result<BTreeMap<String, String>, DeployError> {
        deploy_together(
            &self.secrets,
            &self.public,
            Some(&batch(value, value)),
            Some(&known_hosts(value)),
        )
    }

    /// The secret pair, the public value, and both version maps.
    fn visible(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>, BTreeMap<String, String>) {
        let (first, second) = visible_pair(&self.secrets_root());
        let public = fs::read(self.public_root().join("box/known-hosts")).unwrap();
        let mut versions = self.secrets.current_versions().unwrap();
        versions.extend(self.public.current_versions().unwrap());
        (first, second, public, versions)
    }

    fn pending(&self) -> Vec<String> {
        [self.secrets_root(), self.public_root()]
            .iter()
            .flat_map(|root| fs::read_dir(root).unwrap())
            .map(|item| item.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".current-"))
            .collect()
    }

    fn pointers(&self) -> (PathBuf, PathBuf) {
        (
            fs::read_link(self.secrets_root().join(".current")).unwrap(),
            fs::read_link(self.public_root().join(".current")).unwrap(),
        )
    }
}

fn known_hosts(value: &[u8]) -> ResolvedBatch {
    let mut public = entry("box", "known-hosts", value);
    public.class = SecretClass::PublicInfo;
    public.mode = 0o644;
    ResolvedBatch {
        entries: vec![public],
    }
}

fn old_set() -> (Vec<u8>, Vec<u8>, Vec<u8>, BTreeMap<String, String>) {
    (
        b"old".to_vec(),
        b"old".to_vec(),
        b"old".to_vec(),
        versions_of(b"old"),
    )
}

fn new_set() -> (Vec<u8>, Vec<u8>, Vec<u8>, BTreeMap<String, String>) {
    (
        b"new".to_vec(),
        b"new".to_vec(),
        b"new".to_vec(),
        versions_of(b"new"),
    )
}

fn versions_of(value: &[u8]) -> BTreeMap<String, String> {
    let version = format!("v-{}", value[0]);
    [
        "host.services.mail.first",
        "host.services.git.second",
        "host.services.box.known-hosts",
    ]
    .into_iter()
    .map(|identifier| (identifier.to_owned(), version.clone()))
    .collect()
}

const PREPARE_POINTS: [FailurePoint; 10] = [
    FailurePoint::StorePrepared,
    FailurePoint::BaseCopied,
    FailurePoint::SecretStaged(0),
    FailurePoint::VersionsStaged,
    FailurePoint::GenerationSynced,
    FailurePoint::GenerationPublished,
    FailurePoint::ServiceLinksPrepared,
    FailurePoint::PointerPrepared,
    FailurePoint::GenerationAccessible,
    FailurePoint::SecretStaged(1),
];

#[test]
fn a_value_failing_in_the_second_root_keeps_both_previous_sets() {
    let pair = Pair::new();
    pair.deploy(b"old").unwrap();
    let pointers = pair.pointers();
    // Owner -1 leaves the owner unchanged, so the staged metadata never
    // matches: a staging failure of the last value of the last root.
    let mut secrets = batch(b"new", b"new");
    secrets.entries[1].owner = u32::MAX;
    let error = deploy_together(
        &pair.secrets,
        &pair.public,
        Some(&secrets),
        Some(&known_hosts(b"new")),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("staging host.services.git.second"), "{error}");
    assert!(error.contains(&pair.secrets_root().display().to_string()), "{error}");
    assert_eq!(pair.visible(), old_set());
    assert_eq!(pair.pointers(), pointers);
    assert!(pair.pending().is_empty(), "{:?}", pair.pending());
    pair.deploy(b"new").unwrap();
    assert_eq!(pair.visible(), new_set());
}

#[test]
fn a_failure_while_preparing_either_root_keeps_both_previous_sets() {
    for root in [Root::Public, Root::Secrets] {
        for point in PREPARE_POINTS {
            if root == Root::Public && point == FailurePoint::SecretStaged(1) {
                continue;
            }
            let pair = Pair::new();
            pair.deploy(b"old").unwrap();
            assert!(together_failing_at(
                &pair.secrets,
                &pair.public,
                &batch(b"new", b"new"),
                &known_hosts(b"new"),
                root,
                point,
            )
            .is_err());
            assert_eq!(pair.visible(), old_set(), "{root:?} {point:?}");
            recover(&pair.secrets, &pair.public).unwrap();
            assert_eq!(pair.visible(), old_set(), "{root:?} {point:?}");
            assert!(pair.pending().is_empty(), "{root:?} {point:?}");
            pair.deploy(b"new").unwrap();
            assert_eq!(pair.visible(), new_set(), "{root:?} {point:?}");
        }
    }
}

#[test]
fn every_joint_crash_recovers_to_one_whole_set() {
    let mut points: Vec<(Root, FailurePoint)> = Vec::new();
    for root in [Root::Public, Root::Secrets] {
        for point in PREPARE_POINTS.into_iter().chain([
            FailurePoint::PointerSwitched,
            FailurePoint::PointerSynced,
            FailurePoint::Pruned,
        ]) {
            if !(root == Root::Public && point == FailurePoint::SecretStaged(1)) {
                points.push((root, point));
            }
        }
    }
    for (root, point) in points {
        let pair = Pair::new();
        pair.deploy(b"old").unwrap();
        assert!(together_failing_at(
            &pair.secrets,
            &pair.public,
            &batch(b"new", b"new"),
            &known_hosts(b"new"),
            root,
            point,
        )
        .is_err());
        recover(&pair.secrets, &pair.public).unwrap();
        let visible = pair.visible();
        // The public root switches after the secret root, so any switch
        // point is past the commit.
        let committed = !PREPARE_POINTS.contains(&point);
        if committed {
            assert_eq!(visible, new_set(), "{root:?} {point:?}");
        } else {
            assert_eq!(visible, old_set(), "{root:?} {point:?}");
        }
        assert!(pair.pending().is_empty(), "{root:?} {point:?}");
        let (secrets, public) = pair.pointers();
        assert_eq!(secrets.file_name(), public.file_name(), "{root:?} {point:?}");
    }
}

#[test]
fn a_crash_between_the_switches_is_finished_before_a_public_only_deploy() {
    let pair = Pair::new();
    pair.deploy(b"old").unwrap();
    together_failing_at(
        &pair.secrets,
        &pair.public,
        &batch(b"new", b"new"),
        &known_hosts(b"new"),
        Root::Secrets,
        FailurePoint::PointerSynced,
    )
    .unwrap_err();
    // Mixed until recovery: the new secrets and the old public information.
    assert_eq!(
        fs::read(pair.public_root().join("box/known-hosts")).unwrap(),
        b"old"
    );
    // The public default installer deploys into the public-info root alone.
    let mut other = entry("box", "other", b"default");
    other.class = SecretClass::PublicInfo;
    other.mode = 0o644;
    pair.public
        .deploy(&ResolvedBatch {
            entries: vec![other],
        })
        .unwrap();
    assert_eq!(pair.visible(), new_set_with_public_default());
    recover(&pair.secrets, &pair.public).unwrap();
    assert_eq!(pair.visible(), new_set_with_public_default());
    assert!(pair.pending().is_empty());
}

fn new_set_with_public_default() -> (Vec<u8>, Vec<u8>, Vec<u8>, BTreeMap<String, String>) {
    let (first, second, public, mut versions) = new_set();
    versions.insert("host.services.box.other".into(), "v-100".into());
    (first, second, public, versions)
}

#[test]
fn recovery_without_anything_to_do_changes_nothing() {
    let pair = Pair::new();
    // Absent roots stay absent.
    recover(&pair.secrets, &pair.public).unwrap();
    pair.public.recover_alone().unwrap();
    assert!(!pair.secrets_root().exists() && !pair.public_root().exists());

    pair.deploy(b"old").unwrap();
    let listing = |root: &Path| {
        let mut names: Vec<_> = fs::read_dir(root)
            .unwrap()
            .chain(fs::read_dir(root.join(".generations")).unwrap())
            .map(|item| item.unwrap().path())
            .collect();
        names.sort();
        names
    };
    let before = (
        listing(&pair.secrets_root()),
        listing(&pair.public_root()),
        pair.pointers(),
    );
    for _ in 0..2 {
        recover(&pair.secrets, &pair.public).unwrap();
        pair.public.recover_alone().unwrap();
        assert_eq!(
            (
                listing(&pair.secrets_root()),
                listing(&pair.public_root()),
                pair.pointers()
            ),
            before
        );
        assert_eq!(pair.visible(), old_set());
    }

    // Recovering a crash twice is the same as once.
    together_failing_at(
        &pair.secrets,
        &pair.public,
        &batch(b"new", b"new"),
        &known_hosts(b"new"),
        Root::Secrets,
        FailurePoint::PointerSwitched,
    )
    .unwrap_err();
    recover(&pair.secrets, &pair.public).unwrap();
    let pointers = pair.pointers();
    recover(&pair.secrets, &pair.public).unwrap();
    assert_eq!(pair.pointers(), pointers);
    assert_eq!(pair.visible(), new_set());
}

#[test]
fn a_public_root_must_be_paired_with_the_secret_root() {
    let pair = Pair::new();
    let unpaired = Deployer::at(pair.public_root()).unwrap();
    assert!(recover(&pair.secrets, &unpaired).is_err());
    assert!(deploy_together(&pair.secrets, &unpaired, Some(&batch(b"a", b"b")), None).is_err());
}
