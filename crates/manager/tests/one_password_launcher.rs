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
        fs::write(
            &op,
            format!(
                "#!/bin/sh\necho \"$*\" >> {}\n{body}\n",
                directory.join("calls").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&op, fs::Permissions::from_mode(0o755)).unwrap();
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
