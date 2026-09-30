use super::*;
use std::cell::RefCell;

struct Fake {
    scan: Vec<u8>,
    find: Vec<u8>,
}
impl Runner for Fake {
    fn run(&self, program: &OsStr, _: &[OsString]) -> Result<Output, HostKeyError> {
        let value = if program == OsStr::new("ssh-keyscan") {
            &self.scan
        } else {
            &self.find
        };
        Ok(Output {
            success: !value.is_empty(),
            stdout: value.clone(),
        })
    }
}
fn verifier() -> HostKeyVerifier {
    HostKeyVerifier::new(vec![PathBuf::from("/dev/null")])
}

struct InterruptedScan {
    interrupted: RefCell<bool>,
    keys: Fake,
}
impl Runner for InterruptedScan {
    fn run(&self, program: &OsStr, args: &[OsString]) -> Result<Output, HostKeyError> {
        if program == OsStr::new("ssh-keyscan") && !self.interrupted.replace(true) {
            return Ok(Output { success: false, stdout: Vec::new() });
        }
        self.keys.run(program, args)
    }
}

#[test]
fn interrupted_scan_retries_without_bypassing_host_identity_checks() {
    for (scanned, changed) in [("OLD", false), ("NEW", true)] {
        let runner = InterruptedScan {
            interrupted: RefCell::new(false),
            keys: Fake {
                scan: format!("host ssh-ed25519 {scanned}\n").into_bytes(),
                find: b"host ssh-ed25519 OLD\n".to_vec(),
            },
        };
        let mut decision = |_: &HostIdentity| panic!("known or changed keys must not prompt");
        let result = verifier().verify_with("host", 22, &mut decision, &runner);
        if changed { assert!(matches!(result, Err(HostKeyError::Changed(_)))); }
        else { result.unwrap(); }
    }
}

#[test]
fn known_matching_key_needs_no_decision() {
    let fake = Fake {
        scan: b"host ssh-ed25519 AAAA\n".to_vec(),
        find: b"host ssh-ed25519 AAAA\n".to_vec(),
    };
    let called = RefCell::new(false);
    let mut decision = |_: &HostIdentity| {
        *called.borrow_mut() = true;
        Decision::Reject
    };
    verifier()
        .verify_with("host", 22, &mut decision, &fake)
        .unwrap();
    assert!(!*called.borrow());
}

#[test]
fn changed_key_is_rejected_without_prompt() {
    let fake = Fake {
        scan: b"host ssh-ed25519 NEW\n".to_vec(),
        find: b"host ssh-ed25519 OLD\n".to_vec(),
    };
    let mut decision = |_: &HostIdentity| Decision::Accept;
    assert!(matches!(
        verifier().verify_with("host", 22, &mut decision, &fake),
        Err(HostKeyError::Changed(_))
    ));
}

#[test]
fn unknown_key_requires_explicit_acceptance() {
    let fake = Fake {
        scan: b"host ssh-ed25519 NEW\n".to_vec(),
        find: Vec::new(),
    };
    let mut reject = |_: &HostIdentity| Decision::Reject;
    assert!(matches!(
        verifier().verify_with("host", 22, &mut reject, &fake),
        Err(HostKeyError::UnknownRejected)
    ));
    let mut accept = |identity: &HostIdentity| {
        assert_eq!(identity.keys[0].encoded, "NEW");
        Decision::Accept
    };
    assert!(verifier()
        .verify_with("host", 22, &mut accept, &fake)
        .is_ok());
}

/// ssh-keyscan reports a host's keys in no fixed order. The identity an
/// operator approves must equal the one scanned again before connecting,
/// or an unknown host with several keys can never be deployed.
#[test]
fn the_identity_does_not_depend_on_scan_order() {
    let scan = |order: &[&str]| Fake {
        scan: order
            .iter()
            .map(|key| format!("host {key}\n"))
            .collect::<String>()
            .into_bytes(),
        find: Vec::new(),
    };
    let keys = ["ssh-ed25519 AAAA", "ecdsa-sha2-nistp256 BBBB", "ssh-rsa CCCC"];
    let first = verifier()
        .preflight_with("host", 22, &scan(&keys))
        .unwrap();
    let reversed = verifier()
        .preflight_with("host", 22, &scan(&[keys[2], keys[0], keys[1], keys[0]]))
        .unwrap();
    assert_eq!(first.identity, reversed.identity);
    assert_eq!(first.identity.keys.len(), 3);
    assert_eq!(first.known_host_lines, reversed.known_host_lines);
}

#[test]
fn a_changed_key_names_the_host_the_fingerprints_and_the_fix() {
    use base64::Engine;
    let encode = |byte: u8| {
        let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        blob.extend_from_slice(&[byte; 32]);
        base64::engine::general_purpose::STANDARD.encode(blob)
    };
    let (old, new) = (encode(1), encode(2));
    let fake = Fake {
        scan: format!("ns1.lamk.eu ssh-ed25519 {new}\n").into_bytes(),
        find: format!("# Host ns1.lamk.eu found: line 17\nns1.lamk.eu ssh-ed25519 {old}\n").into_bytes(),
    };
    // The file must exist to be asked; the fake answers for it.
    let file = tempfile_known_hosts();
    let verifier = HostKeyVerifier::new(vec![file.clone()]);
    let error = match verifier.preflight_with("ns1.lamk.eu", 22, &fake) {
        Err(HostKeyError::Changed(changed)) => changed,
        other => panic!("expected a changed key, got {other:?}"),
    };
    let text = error.to_string();
    let old_print = fingerprint(&old);
    let new_print = fingerprint(&new);
    assert!(old_print.starts_with("SHA256:") && old_print != new_print);
    assert!(text.contains("SSH HOST KEY MISMATCH for ns1.lamk.eu:22"), "{text}");
    assert!(
        text.contains(&format!("expected: ssh-ed25519 {old_print} ({} line 17)", file.display())),
        "{text}"
    );
    assert!(text.contains(&format!("offered:  ssh-ed25519 {new_print}")), "{text}");
    assert!(
        text.contains(&format!("`ssh-keygen -R ns1.lamk.eu -f {}`", file.display())),
        "{text}"
    );
    assert!(text.contains("any IP address"), "{text}");
}

#[test]
fn a_non_default_port_is_quoted_for_ssh_keygen() {
    let changed = ChangedHostKey {
        host: "ns1".into(),
        port: 2222,
        expected: vec![KnownKey {
            file: PathBuf::from("/k"),
            line: None,
            key: PresentedKey {
                algorithm: "ssh-ed25519".into(),
                encoded: "AAAA".into(),
            },
        }],
        offered: vec![],
    };
    assert!(changed.to_string().contains("`ssh-keygen -R '[ns1]:2222' -f /k`"));
}

#[test]
fn fingerprints_match_ssh_keygen() {
    // ssh-keygen -lf of this key prints the same.
    assert_eq!(
        fingerprint("AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"),
        "SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA"
    );
}

fn tempfile_known_hosts() -> PathBuf {
    let path = std::env::temp_dir().join(format!("nix-secrets-known-hosts-{}", std::process::id()));
    fs::write(&path, "").unwrap();
    path
}
