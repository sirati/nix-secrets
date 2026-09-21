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
