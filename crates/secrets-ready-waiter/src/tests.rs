use super::*;
use std::os::unix::fs::symlink;
use std::time::{SystemTime, UNIX_EPOCH};

const GENERATION: &str = "000000000000000000000000000000000000001-0000000001";

fn root_entry(path: PathBuf, mode: &str) -> ManifestEntry {
    ManifestEntry {
        path,
        owner: "root".into(),
        group: "root".into(),
        mode: mode.into(),
        runtime_readers: Vec::new(),
        acl_program: None,
    }
}

fn test_root() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    env::temp_dir().join(format!("waiter-test-{}-{unique}", std::process::id()))
}

#[test]
fn parses_the_exact_json_contract() {
    let secrets = parse_manifest(
        r#"[{"path":"/persistent/secrets/mail/service/password","owner":"root","group":"root","mode":"0400"}]"#,
    )
    .unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].mode, 0o400);
}

#[test]
fn rejects_malformed_manifests() {
    assert!(parse_manifest("[]").is_err());
    assert!(parse_manifest("[{}]").is_err());
    assert!(parse_manifest(
        r#"[{"path":"/run/secrets/mail/service/password","owner":"root","group":"root","mode":"0400"}]"#,
    ).is_err());
    assert!(parse_manifest(
        r#"[{"path":"/persistent/secrets/mail/service/password","owner":"root","group":"root","mode":"400"}]"#,
    ).is_err());
}

#[test]
fn rejects_duplicate_paths_unknown_fields_and_unknown_accounts() {
    let duplicate = r#"[
      {"path":"/persistent/secrets/mail/service/password","owner":"root","group":"root","mode":"0400"},
      {"path":"/persistent/secrets/mail/service/password","owner":"root","group":"root","mode":"0400"}
    ]"#;
    assert!(parse_manifest(duplicate).is_err());
    assert!(parse_manifest(
        r#"[{"path":"/persistent/secrets/mail/service/password","owner":"root","group":"root","mode":"0400","extra":true}]"#,
    ).is_err());
    let entry = ManifestEntry {
        owner: "account-that-must-not-exist".into(),
        ..root_entry(
            PathBuf::from("/persistent/secrets/mail/service/password"),
            "0400",
        )
    };
    assert!(resolve_entry(entry).is_err());
}

#[test]
fn accepts_only_the_two_controlled_links_and_exact_metadata() {
    let root = test_root();
    let generation = root.join(".generations").join(GENERATION);
    let category = generation.join("mail/service");
    fs::create_dir_all(&category).unwrap();
    symlink(
        Path::new(".generations").join(GENERATION),
        root.join(".current"),
    )
    .unwrap();
    symlink(".current/mail", root.join("mail")).unwrap();
    let file = category.join("password");
    fs::write(&file, b"not read by the waiter").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    let metadata = fs::symlink_metadata(&file).unwrap();
    let expected = ExpectedSecret {
        path: PathBuf::from("/persistent/secrets/mail/service/password"),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: 0o400,
        runtime_uids: Vec::new(),
        acl_program: None,
    };
    assert_eq!(secret_is_ready_at(&root, &expected), Ok(true));

    fs::set_permissions(&file, fs::Permissions::from_mode(0o440)).unwrap();
    assert_eq!(secret_is_ready_at(&root, &expected), Ok(false));
    fs::remove_file(&file).unwrap();
    symlink("elsewhere", &file).unwrap();
    assert_eq!(secret_is_ready_at(&root, &expected), Ok(false));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_unexpected_structural_link_targets() {
    let root = test_root();
    let generation = root.join(".generations").join(GENERATION);
    fs::create_dir_all(generation.join("mail/service")).unwrap();
    symlink(
        Path::new(".generations").join(GENERATION),
        root.join(".current"),
    )
    .unwrap();
    symlink(".current/other", root.join("mail")).unwrap();
    let expected = ExpectedSecret {
        path: PathBuf::from("/persistent/secrets/mail/service/password"),
        uid: 0,
        gid: 0,
        mode: 0o400,
        runtime_uids: Vec::new(),
        acl_program: None,
    };
    assert!(secret_is_ready_at(&root, &expected).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn validates_generation_ids() {
    assert!(is_generation_id(GENERATION));
    assert!(!is_generation_id("../escape"));
    assert!(!is_generation_id("1-1"));
}

#[test]
fn runtime_acl_rejects_extra_readers_and_overbroad_masks() {
    let exact = "user::r--\nuser:12345:r--\ngroup::---\nmask::r--\nother::---\n";
    assert!(exact_runtime_acl(exact, &[12345]));
    assert!(!exact_runtime_acl(exact, &[12346]));
    assert!(!exact_runtime_acl(
        &format!("{exact}user:12346:r--\n"),
        &[12345]
    ));
    assert!(!exact_runtime_acl(
        &exact.replace("mask::r--", "mask::rw-"),
        &[12345]
    ));
    assert!(!exact_runtime_acl(
        &exact.replace("group::---", "group::r--"),
        &[12345]
    ));
    assert!(!exact_runtime_acl(
        &exact.replace("other::---", "other::r--"),
        &[12345]
    ));
    assert!(!exact_runtime_acl(
        &exact.replace("user:12345:r--", "user:12345:rw-"),
        &[12345]
    ));
}

#[test]
fn subordinate_runtime_uid_is_exact_and_bounded() {
    let reader = RuntimeReader {
        account: "relay".into(),
        uid_offset: 2399,
    };
    assert_eq!(
        resolve_runtime_uid("relay:100000:65536\n", &reader),
        Ok(102399)
    );
    assert!(resolve_runtime_uid("relay:100000:65536\nrelay:200000:65536\n", &reader).is_err());
    assert!(resolve_runtime_uid("relay:100000:2399\n", &reader).is_err());
    assert!(resolve_runtime_uid("relay:4294967294:65536\n", &reader).is_err());
    assert!(resolve_runtime_uid("other:100000:65536\n", &reader).is_err());
}

#[test]
fn readiness_accepts_deployed_then_exact_prepared_acl_and_rejects_extra_reader() {
    let root = test_root();
    let category = root
        .join(".generations")
        .join(GENERATION)
        .join("mail/service");
    fs::create_dir_all(&category).unwrap();
    symlink(
        Path::new(".generations").join(GENERATION),
        root.join(".current"),
    )
    .unwrap();
    symlink(".current/mail", root.join("mail")).unwrap();
    let file = category.join("password");
    fs::write(&file, b"test fixture not read by readiness").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    let metadata = file.metadata().unwrap();
    let mut expected = ExpectedSecret {
        path: PathBuf::from("/persistent/secrets/mail/service/password"),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: 0o400,
        runtime_uids: vec![99999],
        acl_program: Some(PathBuf::from("getfacl")),
    };
    assert_eq!(secret_is_ready_at(&root, &expected), Ok(true));
    let set = |acl: &str| {
        assert!(
            std::process::Command::new("setfacl")
                .args(["-m", acl])
                .arg(&file)
                .status()
                .unwrap()
                .success()
        );
    };
    let probe = std::process::Command::new("setfacl")
        .env("LC_ALL", "C")
        .args(["-m", "u:99999:r--"])
        .arg(&file)
        .output()
        .unwrap();
    if !probe.status.success()
        && String::from_utf8_lossy(&probe.stderr).contains("Operation not supported")
        && std::env::var_os("NIX_SECRETS_REQUIRE_ACL_TEST").is_none()
    {
        eprintln!("real ACL regression unavailable on this filesystem; run on an ACL-capable host");
        fs::remove_dir_all(root).unwrap();
        return;
    }
    assert!(
        probe.status.success(),
        "{}",
        String::from_utf8_lossy(&probe.stderr)
    );
    assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o440);
    assert_eq!(secret_is_ready_at(&root, &expected), Ok(true));
    expected.runtime_uids[0] = 99998;
    assert_eq!(secret_is_ready_at(&root, &expected), Ok(false));
    expected.runtime_uids[0] = 99999;
    set("u:99998:r--");
    assert_eq!(secret_is_ready_at(&root, &expected), Ok(false));
    assert!(
        std::process::Command::new("setfacl")
            .args(["-x", "u:99998"])
            .arg(&file)
            .status()
            .unwrap()
            .success()
    );
    set("g::r--");
    assert_eq!(secret_is_ready_at(&root, &expected), Ok(false));
    fs::remove_dir_all(root).unwrap();
}
