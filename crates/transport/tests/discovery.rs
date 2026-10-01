//! Public discovery API against real bounded child processes, never hosts.
use nix_secrets_transport::{HostKeyStatus, HostKeyVerifier};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn executable(path: &std::path::Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn scenario(mode: &str) {
    let root = Directory(
        std::env::temp_dir().join(format!(
            "ssh-discovery-{mode}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )),
    );
    fs::create_dir(&root.0).unwrap();
    fs::write(root.0.join("known_hosts"), "").unwrap();
    let diagnostics = format!(
        "SCAN-FAILURE-DIAGNOSTIC\x1b[31m\r\u{202e}\u{2066}{}",
        "x".repeat(3000)
    );
    fs::write(root.0.join("diagnostics"), diagnostics).unwrap();
    executable(
        &root.0.join("ssh-keyscan"),
        &format!(
            r#"#!/bin/sh
printf 'attempt\n' >> '{root}/attempts'
printf '%s\n' "$@" >> '{root}/arguments'
count=$(wc -l < '{root}/attempts')
case "$SSH_DISCOVERY_MODE" in
 transient)
  if [ "$count" -eq 1 ]; then exit 0; fi
  if [ "$count" -eq 2 ]; then exit 1; fi
  printf 'host ssh-rsa AA==\n';;
 permanent)
  cat '{root}/diagnostics' >&2
  exit 1;;
 replaced)
  if [ "$count" -eq 1 ]; then printf 'host ssh-rsa AA==\n'; exit 0; fi
  printf 'host ssh-rsa AQ==\n'
  printf 'keyscan returned changed key with failure\n' >&2
  exit 1;;
esac
"#,
            root = root.0.display()
        ),
    );
    executable(&root.0.join("ssh-keygen"), "#!/bin/sh\nexit 1\n");
    executable(
        &root.0.join("ssh"),
        &format!(
            "#!/bin/sh\nprintf 'UNEXPECTED-SSH' > '{}'\nexit 99\n",
            root.0.join("ssh-invoked").display()
        ),
    );
    let search = std::env::join_paths(
        std::iter::once(root.0.clone())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let started = Instant::now();
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "discovery_fixture_process",
            "--nocapture",
        ])
        .env("PATH", search)
        .env("SSH_DISCOVERY_FIXTURE", &root.0)
        .env("SSH_DISCOVERY_MODE", mode)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let attempts = fs::read_to_string(root.0.join("attempts"))
        .unwrap()
        .lines()
        .count();
    assert_eq!(
        attempts,
        match mode {
            "transient" => 3,
            "permanent" => 8,
            _ => 2,
        }
    );
    assert!(
        !root.0.join("ssh-invoked").exists(),
        "discovery unexpectedly opened SSH"
    );
    let args = fs::read_to_string(root.0.join("arguments")).unwrap();
    let lines = args.lines().collect::<Vec<_>>();
    for invocation in lines.chunks_exact(6) {
        assert_eq!(invocation, ["-T", "10", "-p", "22", "--", "host"]);
    }
    assert_eq!(lines.len(), attempts * 6);
    if mode == "transient" {
        assert!(
            started.elapsed().as_millis() >= 3900,
            "real retry delays were bypassed"
        );
    }
    if mode == "permanent" {
        assert!(
            started.elapsed().as_millis() >= 13900,
            "eight attempts must retain actual bounded retry delays"
        );
    }
}
#[test]
fn empty_success_then_failed_scan_then_valid_key_recovers() {
    scenario("transient");
}
#[test]
fn permanent_empty_failures_stop_at_eight_and_sanitize_diagnostics() {
    scenario("permanent");
}
#[test]
fn nonzero_scan_with_replaced_key_is_refused_immediately() {
    scenario("replaced");
}
#[test]
#[ignore = "invoked by scenario tests with an isolated PATH"]
fn discovery_fixture_process() {
    let root = PathBuf::from(std::env::var_os("SSH_DISCOVERY_FIXTURE").unwrap());
    let mode = std::env::var("SSH_DISCOVERY_MODE").unwrap();
    let verifier = HostKeyVerifier::new(vec![root.join("known_hosts")]);
    match mode.as_str() {
        "transient" => {
            let discovered = verifier.preflight("host", 22).unwrap();
            assert_eq!(discovered.status, HostKeyStatus::Unknown);
            assert_eq!(discovered.identity.keys.len(), 1);
            assert_eq!(discovered.identity.keys[0].encoded, "AA==");
        }
        "permanent" => {
            let error = verifier.preflight("host", 22).unwrap_err().to_string();
            assert!(error.contains("8 attempts"), "{error}");
            assert!(error.contains("60-second discovery budget"), "{error}");
            assert!(error.contains("SCAN-FAILURE-DIAGNOSTIC"), "{error}");
            assert!(error.contains("diagnostics truncated"), "{error}");
            assert!(error.len() < 2600, "unbounded diagnostics: {}", error.len());
            assert!(!error.contains('\x1b') && !error.contains('\r'));
            assert!(!error
                .chars()
                .any(|c| matches!(c as u32, 0x202a..=0x202e | 0x2066..=0x2069)));
        }
        _ => {
            let approved = verifier.preflight("host", 22).unwrap().identity;
            let error = verifier
                .preflight_approved("host", 22, &approved)
                .unwrap_err()
                .to_string();
            assert!(error.contains("missing or replaced"), "{error}");
        }
    }
}
