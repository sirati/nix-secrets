//! Exercise the real OpenSSH launcher with process fixtures, without hosts.
use nix_secrets_transport::{Decision, HostKeyStatus, HostKeyVerifier, OpenSsh};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn executable(path: &std::path::Path, source: &str) {
    fs::write(path, source).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn unknown_host_approved_rsa_identity_does_not_trust_a_new_ed25519_key() {
    let root = Directory(std::env::temp_dir().join(format!(
            "ssh-approved-rsa-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    fs::create_dir(&root.0).unwrap();
    fs::write(root.0.join("known_hosts"), "").unwrap();
    fs::write(root.0.join("scan"), "host ssh-rsa AA==\n").unwrap();
    executable(
        &root.0.join("ssh-keyscan"),
        &format!("#!/bin/sh\ncat '{}'\n", root.0.join("scan").display()),
    );
    executable(
        &root.0.join("ssh-keygen"),
        &format!(
            "#!/bin/sh\ncat '{}'\n",
            root.0.join("known_hosts").display()
        ),
    );
    executable(&root.0.join("ssh"), &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nfor arg do\n case \"$arg\" in UserKnownHostsFile=*) cat \"${{arg#UserKnownHostsFile=}}\" > '{}';; esac\ndone\n", root.0.join("arguments").display(), root.0.join("actual-pin").display()));
    let path = std::env::join_paths(
        std::iter::once(root.0.clone())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    // Isolate PATH in a separate test process; parallel tests cannot inherit
    // this fixture or accidentally invoke real network tools.
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "launch_approved_rsa_in_fixture_process",
            "--nocapture",
        ])
        .env("PATH", path)
        .env("SSH_PIN_FIXTURE", &root.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let args = fs::read_to_string(root.0.join("arguments")).unwrap();
    for required in [
        "StrictHostKeyChecking=yes",
        "UpdateHostKeys=no",
        "GlobalKnownHostsFile=/dev/null",
        "KnownHostsCommand=none",
        "VerifyHostKeyDNS=no",
        "HostKeyAlgorithms=rsa-sha2-512,rsa-sha2-256",
    ] {
        assert!(
            args.lines().any(|line| line == required),
            "missing {required}: {args}"
        );
    }
    assert!(
        !args
            .lines()
            .filter(|line| line.starts_with("HostKeyAlgorithms="))
            .any(|line| line
                .split('=')
                .nth(1)
                .unwrap()
                .split(',')
                .any(|algorithm| algorithm == "ssh-rsa" || algorithm == "ssh-ed25519")),
        "unapproved or SHA1 algorithm enabled: {args}"
    );
    assert_eq!(
        fs::read_to_string(root.0.join("actual-pin")).unwrap(),
        "host ssh-rsa AA==\n"
    );
    assert!(!fs::read_to_string(root.0.join("actual-pin"))
        .unwrap()
        .contains("ssh-ed25519"));
    let pin = args
        .lines()
        .find_map(|arg| arg.strip_prefix("UserKnownHostsFile="))
        .unwrap();
    assert!(
        !std::path::Path::new(pin).exists(),
        "temporary pin survived SSH session"
    );
}

#[test]
#[ignore = "invoked by parent test with isolated process fixtures"]
fn launch_approved_rsa_in_fixture_process() {
    let root = PathBuf::from(std::env::var_os("SSH_PIN_FIXTURE").unwrap());
    let verifier = HostKeyVerifier::new(vec![root.join("known_hosts")]);
    let first = verifier.preflight("host", 22).unwrap();
    assert_eq!(first.status, HostKeyStatus::Unknown);
    let approved = first.identity;
    assert_eq!(approved.keys.len(), 1);
    fs::write(
        root.join("scan"),
        "host ssh-rsa AA==\nhost ssh-ed25519 AQ==\n",
    )
    .unwrap();
    let checked = verifier.preflight_approved("host", 22, &approved).unwrap();
    assert_eq!(checked.identity, approved);
    let ssh = OpenSsh {
        program: root.join("ssh").into_os_string(),
        destination: "forward@host".into(),
        host: "host".into(),
        port: 22,
        verifier,
        identities: vec![],
    };
    assert!(ssh
        .connect_preflight(checked, Decision::Accept)
        .unwrap()
        .wait()
        .unwrap()
        .success());
}
