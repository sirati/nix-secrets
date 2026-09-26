use super::*;
use std::fs;

pub(crate) fn git(directory: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// A repository with one commit of an unrelated file and the secret store.
pub(crate) fn repository() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    git(path, &["init", "-q", "-b", "main"]);
    for (key, value) in [
        ("user.name", "test"),
        ("user.email", "test@example.invalid"),
        ("commit.gpgsign", "false"),
    ] {
        git(path, &["config", key, value]);
    }
    fs::write(path.join("flake.nix"), "{ }\n").unwrap();
    fs::write(path.join("nix-secrets.toml"), "[secrets]\n").unwrap();
    git(path, &["add", "."]);
    git(path, &["commit", "-q", "-m", "initial"]);
    directory
}

fn options(message: &str) -> CommitOptions {
    CommitOptions {
        message: message.into(),
        amend: false,
        signoff: false,
    }
}

fn committed_files(path: &Path) -> Vec<String> {
    git(path, &["show", "--name-only", "--format=", "HEAD"])
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn commits_only_the_managed_files() {
    let directory = repository();
    let path = directory.path();
    fs::write(path.join("nix-secrets.toml"), "[secrets]\n# changed\n").unwrap();
    fs::write(path.join("nix-secrets-profiles.toml"), "revision = 1\n").unwrap();
    fs::write(path.join("flake.nix"), "{ changed = true; }\n").unwrap();
    fs::write(path.join("notes.txt"), "untracked\n").unwrap();
    let repository = Repository::new(path);
    let summary = repository.summary().unwrap();
    assert!(
        summary.diff_stat.contains("nix-secrets.toml"),
        "{summary:?}"
    );
    assert!(
        summary.diff_stat.contains("nix-secrets-profiles.toml"),
        "{summary:?}"
    );
    assert!(!summary.diff_stat.contains("flake.nix"), "{summary:?}");
    assert_eq!(summary.head_message.as_deref(), Some("initial"));
    assert!(summary.foreign_staged.is_empty());

    let result = repository.commit(&options("Store secrets"), None).unwrap();
    assert_eq!(result.hash, git(path, &["rev-parse", "HEAD"]).trim());
    assert!(result.output.ends_with("Store secrets"), "{result:?}");
    assert_eq!(
        committed_files(path),
        ["nix-secrets-profiles.toml", "nix-secrets.toml"]
    );
    // Unrelated work stays in the working tree, unstaged.
    let status = git(path, &["status", "--porcelain"]);
    assert!(status.contains(" M flake.nix"), "{status}");
    assert!(status.contains("?? notes.txt"), "{status}");
}

#[test]
fn refuses_while_other_changes_are_staged_or_the_message_is_empty() {
    let directory = repository();
    let path = directory.path();
    fs::write(path.join("nix-secrets.toml"), "[secrets]\n# changed\n").unwrap();
    let repository = Repository::new(path);
    assert!(repository.commit(&options("  \n"), None).is_err());
    fs::write(path.join("flake.nix"), "{ staged = true; }\n").unwrap();
    git(path, &["add", "flake.nix"]);
    assert_eq!(repository.summary().unwrap().foreign_staged, ["flake.nix"]);
    let error = repository.commit(&options("Store"), None).unwrap_err();
    assert!(error.contains("flake.nix"), "{error}");
    assert_eq!(git(path, &["rev-list", "--count", "HEAD"]).trim(), "1");
    // The managed file was not staged by the refused attempt.
    assert!(!git(path, &["diff", "--cached", "--name-only"]).contains("nix-secrets.toml"));
}

#[test]
fn amends_and_signs_off() {
    let directory = repository();
    let path = directory.path();
    let repository = Repository::new(path);
    fs::write(path.join("nix-secrets.toml"), "[secrets]\n# one\n").unwrap();
    repository.commit(&options("First"), None).unwrap();
    fs::write(path.join("nix-secrets.toml"), "[secrets]\n# two\n").unwrap();
    // An empty message with amend keeps the message of HEAD.
    let amended = repository
        .commit(
            &CommitOptions {
                message: String::new(),
                amend: true,
                signoff: true,
            },
            None,
        )
        .unwrap();
    assert_eq!(git(path, &["rev-list", "--count", "HEAD"]).trim(), "2");
    let message = git(path, &["log", "-1", "--format=%B"]);
    assert!(message.starts_with("First\n"), "{message}");
    assert!(
        message.contains("Signed-off-by: test <test@example.invalid>"),
        "{message}"
    );
    assert!(git(path, &["show", "HEAD:nix-secrets.toml"]).contains("# two"));
    assert_eq!(amended.hash, git(path, &["rev-parse", "HEAD"]).trim());
}
