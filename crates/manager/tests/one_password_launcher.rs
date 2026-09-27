//! The launcher authorizes once through `op`, then runs its program as the
//! leader of a fresh session without a controlling terminal.
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::{env, fs};

struct FakeOp(PathBuf);

impl FakeOp {
    /// An `op` that logs each call and then runs `body`.
    fn new(body: &str) -> Self {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let suffix = random.map(|byte| format!("{byte:02x}")).concat();
        let directory = env::temp_dir().join(format!("nix-secrets-fake-op-{suffix}"));
        fs::create_dir(&directory).unwrap();
        let op = directory.join("op");
        // Renamed into place: executing a file another test thread's child
        // still holds open for writing fails with ETXTBSY.
        let staging = directory.join(".op.tmp");
        fs::write(
            &staging,
            format!(
                "#!/bin/sh\necho \"$*\" >> {}\n{body}\n",
                directory.join("calls").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&staging, &op).unwrap();
        Self(directory)
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.0.join("calls")).unwrap_or_default()
    }

    fn run(&self, arguments: &[&str]) -> Output {
        let path = env::join_paths(
            std::iter::once(self.0.clone())
                .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default())),
        )
        .unwrap();
        Command::new(env!("CARGO_BIN_EXE_nix-secrets-1password"))
            .args(arguments)
            .env("PATH", path)
            .output()
            .unwrap()
    }
}

impl Drop for FakeOp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn stat_fields(stat: &str) -> (String, String, String) {
    // After the command name: state, ppid, pgrp, session, tty_nr.
    let fields: Vec<&str> = stat.rsplit_once(") ").unwrap().1.split(' ').collect();
    (fields[1].into(), fields[3].into(), fields[4].into())
}

#[test]
fn authorized_launcher_leads_a_new_session_and_forwards_the_exit_code() {
    let op = FakeOp::new("exit 0");
    let output = op.run(&[
        "sh",
        "-c",
        "read -r stat < /proc/self/stat; echo \"$stat\"; exit 7",
    ]);
    assert_eq!(output.status.code(), Some(7));
    let (parent, session, tty) = stat_fields(&String::from_utf8(output.stdout).unwrap());
    assert_eq!(session, parent, "the launcher leads the program's session");
    assert_eq!(tty, "0", "has no controlling terminal");
    assert_eq!(
        op.calls(),
        "vault list --format=json\n",
        "one authorization"
    );
}

#[test]
fn denied_authorization_stops_before_the_program_runs() {
    let op = FakeOp::new(
        "echo '[ERROR] 2026/09/25 17:40:00 authorization prompt dismissed, please try again' >&2\nexit 1",
    );
    let marker = op.0.join("program-ran");
    let output = op.run(&["touch", marker.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(77));
    assert!(
        !Path::new(&marker).exists(),
        "age never starts after a denial"
    );
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "nix-secrets-1password: 1Password authorization failed: \
         authorization prompt dismissed, please try again\n"
    );
    assert_eq!(op.calls(), "vault list --format=json\n", "no second prompt");
}

#[test]
fn shared_session_keeps_the_callers_session() {
    let op = FakeOp::new("exit 0");
    let output = op.run(&[
        "--shared-session",
        "sh",
        "-c",
        "read -r stat < /proc/self/stat; echo \"$stat\"",
    ]);
    assert!(output.status.success());
    let (_, session, _) = stat_fields(&String::from_utf8(output.stdout).unwrap());
    let own = fs::read_to_string("/proc/self/stat").unwrap();
    assert_eq!(session, stat_fields(&own).1, "no new session");
}

fn frame(values: &[&[u8]]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| {
            (value.len() as u32)
                .to_be_bytes()
                .into_iter()
                .chain(value.iter().copied())
        })
        .collect()
}

#[test]
fn a_batch_authorizes_once_and_runs_the_program_per_input() {
    use std::io::Write;
    use std::process::Stdio;
    let op = FakeOp::new("exit 0");
    let path = env::join_paths(
        std::iter::once(op.0.clone())
            .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default())),
    )
    .unwrap();
    let runs = op.0.join("runs");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nix-secrets-1password"))
        .args(["--batch", "sh", "-c"])
        .arg(format!("echo run >> '{}'; tr a-z A-Z", runs.display()))
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame(&[b"first", b"", b"third\0value"]))
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, frame(&[b"FIRST", b"", b"THIRD\0VALUE"]));
    assert_eq!(
        op.calls(),
        "vault list --format=json\n",
        "one authorization"
    );
    assert_eq!(fs::read_to_string(runs).unwrap().lines().count(), 3);
}

/// A deployment's whole batch costs one `op item list` (metadata only) and
/// one `op read` of exactly the key that decrypts it. No other SSH key in
/// the account is read, and age-plugin-1p is not used.
#[test]
fn one_key_reads_only_the_matching_private_key_for_a_whole_batch() {
    use std::io::Write;
    use std::process::Stdio;
    let scratch = tempfile::tempdir().unwrap();
    let key = scratch.path().join("id");
    let other = scratch.path().join("other");
    for path in [&key, &other] {
        assert!(Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .status()
            .unwrap()
            .success());
    }
    let fingerprint = |path: &Path| {
        let output = Command::new("ssh-keygen")
            .args(["-l", "-E", "sha256", "-f"])
            .arg(path.with_extension("pub"))
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().split_whitespace().nth(1).unwrap().to_owned()
    };
    let public = fs::read_to_string(key.with_extension("pub")).unwrap();
    let encrypt = |plain: &[u8]| {
        let mut child = Command::new("age")
            .args(["--encrypt", "--recipient", public.trim()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(plain).unwrap();
        child.wait_with_output().unwrap().stdout
    };
    let items = format!(
        r#"[{{"id":"otheritem","title":"Other","vault":{{"id":"vault1"}},"additional_information":"{}"}},
            {{"id":"ititem","title":"IT Secrets","vault":{{"id":"vault1"}},"additional_information":"{}"}}]"#,
        fingerprint(&other),
        fingerprint(&key)
    );
    fs::write(scratch.path().join("items.json"), items).unwrap();
    let op = FakeOp::new(&format!(
        "case \"$1 $2\" in\n\
         'item list') cat {items} ;;\n\
         'read op://vault1/ititem/private key') cat {key} ;;\n\
         *) echo \"unexpected op call: $*\" >&2; exit 9 ;;\n\
         esac",
        items = scratch.path().join("items.json").display(),
        key = key.display(),
    ));
    let path = env::join_paths(
        std::iter::once(op.0.clone())
            .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default())),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nix-secrets-1password"))
        .args(["--batch", "--one-key", "age", "--decrypt"])
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let first = encrypt(b"first");
    let second = encrypt(b"second");
    let third = encrypt(b"third");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame(&[&first, &second, &third]))
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout, frame(&[b"first", b"second", b"third"]));
    assert_eq!(
        op.calls(),
        "item list --categories SSH Key --format=json\nread op://vault1/ititem/private key\n",
        "one listing and one read of the one key, for three values"
    );
}
