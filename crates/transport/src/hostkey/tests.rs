use super::*;
use std::cell::RefCell;

struct Fake {
    scan: Vec<u8>,
    find: Vec<u8>,
}
impl Runner for Fake {
    fn pause(&self, _: std::time::Duration) {}
    fn run(&self, program: &OsStr, _: &[OsString]) -> Result<Output, HostKeyError> {
        let value = if program == OsStr::new("ssh-keyscan") {
            &self.scan
        } else {
            &self.find
        };
        Ok(Output {
            success: !value.is_empty(),
            stdout: value.clone(),
            diagnostic: "fixture failure".into(),
        })
    }
}
fn verifier() -> HostKeyVerifier {
    HostKeyVerifier::new(vec![PathBuf::from("/dev/null")])
}

struct PartialScan {
    scans: RefCell<usize>,
    eventually_complete: bool,
    changed: bool,
}
impl Runner for PartialScan {
    fn pause(&self, _: std::time::Duration) {}
    fn run(&self, program: &OsStr, _: &[OsString]) -> Result<Output, HostKeyError> {
        if program != OsStr::new("ssh-keyscan") {
            return Ok(Output {
                success: false,
                stdout: Vec::new(),
                diagnostic: "fixture failure".into(),
            });
        }
        let mut scans = self.scans.borrow_mut();
        *scans += 1;
        let data = if self.changed {
            "host ssh-rsa NEW\n"
        } else if self.eventually_complete && *scans > 1 {
            "host ssh-ed25519 ED\nhost ssh-rsa RSA\n"
        } else {
            "host ssh-rsa RSA\n"
        };
        Ok(Output {
            success: true,
            stdout: data.as_bytes().to_vec(),
            diagnostic: "fixture failure".into(),
        })
    }
}

#[test]
fn approved_identity_requires_all_keys_but_retries_partial_scans() {
    let approved = verifier()
        .preflight_with(
            "host",
            22,
            &Fake {
                scan: b"host ssh-ed25519 ED\nhost ssh-rsa RSA\n".to_vec(),
                find: Vec::new(),
            },
        )
        .unwrap()
        .identity;
    for (complete, changed) in [(true, false), (false, false), (false, true)] {
        let runner = PartialScan {
            scans: RefCell::new(0),
            eventually_complete: complete,
            changed,
        };
        let result = verifier().preflight_approved_with("host", 22, &approved, &runner);
        if changed {
            assert!(matches!(result, Err(HostKeyError::Tool(_))));
            assert_eq!(*runner.scans.borrow(), 1, "changed keys are not retried");
        } else if complete {
            assert_eq!(result.unwrap().identity, approved);
            assert_eq!(*runner.scans.borrow(), 2);
        } else {
            assert!(matches!(result, Err(HostKeyError::Tool(_))));
            assert_eq!(
                *runner.scans.borrow(),
                3,
                "partial identities must fail closed"
            );
        }
    }
}

struct InterruptedScan {
    interrupted: RefCell<bool>,
    keys: Fake,
}
impl Runner for InterruptedScan {
    fn pause(&self, _: std::time::Duration) {}
    fn run(&self, program: &OsStr, args: &[OsString]) -> Result<Output, HostKeyError> {
        if program == OsStr::new("ssh-keyscan") && !self.interrupted.replace(true) {
            return Ok(Output {
                success: false,
                stdout: Vec::new(),
                diagnostic: "fixture failure".into(),
            });
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
        if changed {
            assert!(matches!(result, Err(HostKeyError::Changed(_))));
        } else {
            result.unwrap();
        }
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
    let keys = [
        "ssh-ed25519 AAAA",
        "ecdsa-sha2-nistp256 BBBB",
        "ssh-rsa CCCC",
    ];
    let first = verifier().preflight_with("host", 22, &scan(&keys)).unwrap();
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
        find: format!("# Host ns1.lamk.eu found: line 17\nns1.lamk.eu ssh-ed25519 {old}\n")
            .into_bytes(),
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
    assert!(
        text.contains("SSH HOST KEY MISMATCH for ns1.lamk.eu:22"),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "expected: ssh-ed25519 {old_print} ({} line 17)",
            file.display()
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!("offered:  ssh-ed25519 {new_print}")),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "`ssh-keygen -R ns1.lamk.eu -f {}`",
            file.display()
        )),
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
    assert!(changed
        .to_string()
        .contains("`ssh-keygen -R '[ns1]:2222' -f /k`"));
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

#[test]
fn added_keys_are_discarded_and_only_approved_keys_remain_pinned() {
    let approved = verifier()
        .preflight_with(
            "host",
            22,
            &Fake {
                scan: b"host ssh-rsa RSA\n".to_vec(),
                find: Vec::new(),
            },
        )
        .unwrap()
        .identity;
    let checked = verifier()
        .preflight_approved_with(
            "host",
            22,
            &approved,
            &Fake {
                scan: b"host ssh-rsa RSA\nhost ssh-ed25519 NEW\n".to_vec(),
                find: Vec::new(),
            },
        )
        .unwrap();
    assert_eq!(checked.identity, approved);
    assert_eq!(checked.known_host_lines, vec!["host ssh-rsa RSA"]);
    assert!(checked.known.is_empty());
}

#[test]
fn replacement_plus_new_algorithm_is_not_an_additive_discovery() {
    let approved = verifier()
        .preflight_with(
            "host",
            22,
            &Fake {
                scan: b"host ssh-rsa RSA\n".to_vec(),
                find: Vec::new(),
            },
        )
        .unwrap()
        .identity;
    let result = verifier().preflight_approved_with(
        "host",
        22,
        &approved,
        &Fake {
            scan: b"host ssh-rsa REPLACED\nhost ssh-ed25519 NEW\n".to_vec(),
            find: Vec::new(),
        },
    );
    assert!(matches!(result, Err(HostKeyError::Tool(_))));
}

#[test]
fn empty_discovery_stops_at_total_budget_before_attempt_limit() {
    struct Budget {
        elapsed: RefCell<std::time::Duration>,
        scans: RefCell<usize>,
    }
    impl Runner for Budget {
        fn run(&self, _: &OsStr, _: &[OsString]) -> Result<Output, HostKeyError> {
            *self.scans.borrow_mut() += 1;
            *self.elapsed.borrow_mut() += std::time::Duration::from_secs(10);
            Ok(Output {
                success: false,
                stdout: Vec::new(),
                diagnostic: "fixture timeout".into(),
            })
        }
        fn elapsed(&self, _: std::time::Instant) -> std::time::Duration {
            *self.elapsed.borrow()
        }
        fn pause(&self, duration: std::time::Duration) {
            *self.elapsed.borrow_mut() += duration;
        }
    }
    let runner = Budget {
        elapsed: RefCell::new(std::time::Duration::ZERO),
        scans: RefCell::new(0),
    };
    let error = verifier().preflight_with("host", 22, &runner).unwrap_err();
    assert_eq!(*runner.scans.borrow(), 5);
    assert_eq!(*runner.elapsed.borrow(), DISCOVERY_BUDGET);
    assert!(error.to_string().contains("5 attempts"));
    assert!(error.to_string().contains("fixture timeout"));
}

#[test]
fn process_scan_deadline_kills_a_stalled_tool() {
    let started = std::time::Instant::now();
    let result = ProcessRunner
        .run_bounded(
            OsStr::new("sh"),
            &["-c".into(), "exec sleep 10".into()],
            std::time::Duration::from_millis(50),
        )
        .unwrap();
    assert!(!result.success);
    assert!(result.diagnostic.contains("process deadline"));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn inherited_output_pipes_cannot_extend_the_scan_deadline() {
    let started = std::time::Instant::now();
    let result = ProcessRunner
        .run_bounded(
            OsStr::new("sh"),
            &[
                "-c".into(),
                "printf 'host ssh-rsa OBSERVED\n'; sleep 0.2 & exit 1".into(),
            ],
            std::time::Duration::from_millis(50),
        )
        .unwrap();
    assert!(!result.success);
    assert!(result.diagnostic.contains("drain deadline"));
    assert!(started.elapsed() < std::time::Duration::from_millis(180));
    assert_eq!(parse_key_lines(&result.stdout)[0].encoded, "OBSERVED");
}

#[test]
fn real_keyscan_natural_inactivity_exit_is_not_a_runner_timeout() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = stop.clone();
    let server = std::thread::spawn(move || {
        let mut connections = Vec::new();
        while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((connection, _)) => connections.push(connection),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(error) => panic!("local listener: {error}"),
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    });
    let result = ProcessRunner.run_bounded(
        OsStr::new("ssh-keyscan"),
        &[
            "-T".into(),
            "1".into(),
            "-p".into(),
            port.to_string().into(),
            "--".into(),
            "127.0.0.1".into(),
        ],
        std::time::Duration::from_secs(2),
    );
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    server.join().unwrap();
    let output = result.expect("actual ssh-keyscan must be available for transport tests");
    assert!(!output.success);
    assert!(output.stdout.is_empty());
    assert!(
        output.diagnostic.starts_with("exit status:"),
        "{}",
        output.diagnostic
    );
}

#[test]
fn fractional_discovery_budget_never_starts_an_over_budget_scan() {
    struct AlmostExpired;
    impl Runner for AlmostExpired {
        fn run(&self, _: &OsStr, _: &[OsString]) -> Result<Output, HostKeyError> {
            panic!("insufficient budget for inactivity timeout plus drain");
        }
        fn elapsed(&self, _: std::time::Instant) -> std::time::Duration {
            DISCOVERY_BUDGET - std::time::Duration::from_millis(1999)
        }
    }
    let error = verifier()
        .preflight_with("host", 22, &AlmostExpired)
        .unwrap_err();
    assert!(error.to_string().contains("after 0 attempts"));
}

#[test]
fn scanner_inactivity_timeout_leaves_a_whole_second_for_drain() {
    struct Budget(std::time::Duration);
    impl Runner for Budget {
        fn run(&self, _: &OsStr, _: &[OsString]) -> Result<Output, HostKeyError> {
            Ok(Output {
                success: false,
                stdout: Vec::new(),
                diagnostic: "no recorded host key".into(),
            })
        }
        fn run_bounded(
            &self,
            _: &OsStr,
            arguments: &[OsString],
            wall: std::time::Duration,
        ) -> Result<Output, HostKeyError> {
            let inactivity: u64 = arguments[1].to_str().unwrap().parse().unwrap();
            assert_eq!(wall, self.0.min(std::time::Duration::from_secs(10)));
            assert!(std::time::Duration::from_secs(inactivity + 1) <= wall);
            Ok(Output {
                success: false,
                stdout: b"host ssh-ed25519 OBSERVED\n".to_vec(),
                diagnostic: "nonzero scan still preserves keys".into(),
            })
        }
        fn elapsed(&self, _: std::time::Instant) -> std::time::Duration {
            DISCOVERY_BUDGET - self.0
        }
    }
    for remaining in [
        std::time::Duration::from_secs(60),
        std::time::Duration::from_millis(2999),
        std::time::Duration::from_secs(2),
    ] {
        assert!(verifier()
            .preflight_with("host", 22, &Budget(remaining))
            .is_ok());
    }
}

#[test]
fn complementary_approved_subsets_accumulate_but_later_replacements_do_not() {
    struct Complementary {
        scans: RefCell<usize>,
        replacement: bool,
    }
    impl Runner for Complementary {
        fn pause(&self, _: std::time::Duration) {}
        fn run(&self, program: &OsStr, _: &[OsString]) -> Result<Output, HostKeyError> {
            if program != OsStr::new("ssh-keyscan") {
                return Ok(Output {
                    success: false,
                    stdout: Vec::new(),
                    diagnostic: "no recorded key".into(),
                });
            }
            let mut scans = self.scans.borrow_mut();
            *scans += 1;
            let data = if *scans == 1 {
                "host ssh-rsa RSA\n"
            } else if self.replacement {
                "host ssh-ed25519 ED\nhost ssh-rsa REPLACED\n"
            } else {
                "host ssh-ed25519 ED\n"
            };
            Ok(Output {
                success: false,
                stdout: data.as_bytes().to_vec(),
                diagnostic: "partial nonzero scan".into(),
            })
        }
    }
    let approved = verifier()
        .preflight_with(
            "host",
            22,
            &Fake {
                scan: b"host ssh-ed25519 ED\nhost ssh-rsa RSA\n".to_vec(),
                find: Vec::new(),
            },
        )
        .unwrap()
        .identity;
    for replacement in [false, true] {
        let runner = Complementary {
            scans: RefCell::new(0),
            replacement,
        };
        let result = verifier().preflight_approved_with("host", 22, &approved, &runner);
        assert_eq!(*runner.scans.borrow(), 2);
        if replacement {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("changed after approval"));
        } else {
            let checked = result.unwrap();
            assert_eq!(checked.identity, approved);
            assert_eq!(checked.known_host_lines.len(), 2);
            assert!(checked
                .known_host_lines
                .contains(&"host ssh-rsa RSA".to_owned()));
            assert!(checked
                .known_host_lines
                .contains(&"host ssh-ed25519 ED".to_owned()));
        }
    }
}
