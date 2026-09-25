//! The launcher must lead a fresh session without a controlling terminal and
//! pass through the exit status of the program it runs.
use std::process::Command;

#[test]
fn launcher_leads_a_new_session_and_forwards_the_exit_code() {
    let launcher = env!("CARGO_BIN_EXE_nix-secrets-1password");
    let output = Command::new(launcher)
        .args([
            "sh",
            "-c",
            "read -r stat < /proc/self/stat; echo \"$stat\"; exit 7",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    let stat = String::from_utf8(output.stdout).unwrap();
    let fields: Vec<&str> = stat.rsplit_once(") ").unwrap().1.split(' ').collect();
    // After the command name: state, ppid, pgrp, session, tty_nr.
    let (parent, session, tty) = (fields[1], fields[3], fields[4]);
    assert_eq!(session, parent, "the launcher leads the shell's session");
    assert_eq!(tty, "0", "has no controlling terminal");
}
