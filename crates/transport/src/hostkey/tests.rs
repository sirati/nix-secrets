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
        Err(HostKeyError::Changed)
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
