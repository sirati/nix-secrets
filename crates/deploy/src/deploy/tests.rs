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
