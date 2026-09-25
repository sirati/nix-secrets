use super::*;
use std::process::Command;

const ID: &str = "host.services.mail.password";

fn record(version: &str, ciphertext: &str) -> String {
    format!(
        "[secrets.\"{ID}\"]\nformat_version = 1\nversion_id = \"{version}\"\nrecipient_ids = [\"operator\"]\nage_ciphertext = \"{ciphertext}\"\n"
    )
}

fn git(directory: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args([
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
        ])
        .args(["-c", "commit.gpgsign=false"])
        .args(arguments)
        .output()
        .unwrap();
    assert!(status.status.success(), "{status:?}");
}

#[test]
fn compares_the_current_record_with_head() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nix-secrets.toml");
    let store = SecretStore::new(&path);
    let id = SecretPath::parse(ID).unwrap();
    assert_eq!(store.commit_state(&id).unwrap(), CommitState::Unset);

    fs::write(&path, record("AAAAAAAAAAAAAAAAAAAAAA==", "YWdl")).unwrap();
    assert!(
        matches!(
            store.commit_state(&id).unwrap(),
            CommitState::Unknown { .. }
        ),
        "no repository means unknown"
    );

    git(directory.path(), &["init", "-q"]);
    git(directory.path(), &["add", "nix-secrets.toml"]);
    git(directory.path(), &["commit", "-q", "-m", "first"]);
    assert_eq!(store.commit_state(&id).unwrap(), CommitState::Committed);

    fs::write(&path, record("BBBBBBBBBBBBBBBBBBBBBA==", "YWdlMg==")).unwrap();
    assert_eq!(store.commit_state(&id).unwrap(), CommitState::Uncommitted);
}
