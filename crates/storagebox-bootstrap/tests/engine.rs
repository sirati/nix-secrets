use nix_secrets_storagebox_bootstrap::*;
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;
use time::{Date, Month};
use zeroize::Zeroizing;

struct PartialSink {
    bytes: Rc<RefCell<Vec<u8>>>,
}
impl Write for PartialSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let count = input.len().min(3);
        self.bytes.borrow_mut().extend_from_slice(&input[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Generator {
    calls: Rc<RefCell<usize>>,
    entropy: Rc<RefCell<Vec<u8>>>,
}
impl KeyGenerator for Generator {
    fn generate(&mut self) -> Result<GeneratedKey, Error> {
        assert_eq!(
            self.entropy.borrow().len(),
            32,
            "generation preceded entropy contribution"
        );
        *self.calls.borrow_mut() += 1;
        OsKeyGenerator.generate()
    }
}

#[derive(Clone)]
struct Backend {
    state: Rc<RefCell<State>>,
    fail_write: bool,
}
#[derive(Default)]
struct State {
    file: Vec<u8>,
    writes: usize,
    password_seen: bool,
    validated: bool,
}
struct Session {
    state: Rc<RefCell<State>>,
    fail_write: bool,
}

impl SshBackend for Backend {
    type Session = Session;
    fn connect(&mut self, task: &StorageBoxTask, password: &[u8]) -> Result<Session, Error> {
        task.validate()?;
        let mut state = self.state.borrow_mut();
        state.password_seen = password == b"password" || password == b"pw";
        state.validated = true;
        drop(state);
        Ok(Session {
            state: self.state.clone(),
            fail_write: self.fail_write,
        })
    }
}
impl RemoteSession for Session {
    fn read_authorized_keys(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.state.borrow().file.clone())
    }
    fn replace_authorized_keys_atomically(&mut self, contents: &[u8]) -> Result<(), Error> {
        if self.fail_write {
            return Err(Error::Ssh("injected failure".into()));
        }
        let mut state = self.state.borrow_mut();
        state.file = contents.to_vec();
        state.writes += 1;
        Ok(())
    }
}

struct FixedClock;
impl Clock for FixedClock {
    fn utc_date(&self) -> Result<Date, Error> {
        Ok(Date::from_calendar_date(2026, Month::September, 22).unwrap())
    }
}

fn task() -> StorageBoxTask {
    let host_key = OsKeyGenerator.generate().unwrap().public_key;
    StorageBoxTask {
        schema_version: 1,
        task_id: "postgres-backup".into(),
        target_hostname: "hetzner2".into(),
        storage_box_host: "u123.your-storagebox.de".into(),
        storage_box_user: "u123".into(),
        port: 23,
        pinned_host_keys: vec![host_key],
        output: Output {
            path: "/persistent/secrets/postgres/backup/key".into(),
            owner: "postgres".into(),
            group: "postgres".into(),
            mode: 0o400,
        },
    }
}

fn engine(
    fail_write: bool,
) -> (
    Engine<Backend, PartialSink, Generator, FixedClock>,
    Rc<RefCell<State>>,
    Rc<RefCell<usize>>,
) {
    let state = Rc::new(RefCell::new(State::default()));
    let calls = Rc::new(RefCell::new(0));
    let entropy = Rc::new(RefCell::new(Vec::new()));
    let value = Engine {
        backend: Backend {
            state: state.clone(),
            fail_write,
        },
        entropy: PartialSink {
            bytes: entropy.clone(),
        },
        generator: Generator {
            calls: calls.clone(),
            entropy,
        },
        clock: FixedClock,
    };
    (value, state, calls)
}

#[test]
fn writes_all_contribution_before_generating_and_reconciles_remote() {
    let (mut engine, state, calls) = engine(false);
    let contribution = [7_u8; 32];
    let result = engine
        .run(
            &task(),
            Zeroizing::new(b"password".to_vec()),
            ClientContribution::new(contribution),
            None,
        )
        .unwrap();
    assert_eq!(*engine.entropy.bytes.borrow(), contribution);
    assert_eq!(*calls.borrow(), 1);
    assert!(state.borrow().password_seen);
    assert!(
        result
            .private_pem
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
    assert!(
        String::from_utf8(state.borrow().file.clone())
            .unwrap()
            .contains("nix-secrets:hetzner2:postgres-backup:2026-09-22")
    );
}

#[test]
fn existing_key_is_reused_and_second_run_does_not_write() {
    let (mut engine, state, calls) = engine(false);
    let first = engine
        .run(
            &task(),
            Zeroizing::new(b"pw".to_vec()),
            ClientContribution::new([1; 32]),
            None,
        )
        .unwrap();
    let second = engine
        .run(
            &task(),
            Zeroizing::new(b"pw".to_vec()),
            ClientContribution::new([2; 32]),
            Some(&first.private_pem),
        )
        .unwrap();
    assert_eq!(first.public_key, second.public_key);
    assert_eq!(*calls.borrow(), 1);
    assert_eq!(state.borrow().writes, 1);
}

#[test]
fn remote_failure_returns_no_publishable_key() {
    let (mut engine, state, _) = engine(true);
    let result = engine.run(
        &task(),
        Zeroizing::new(b"pw".to_vec()),
        ClientContribution::new([3; 32]),
        None,
    );
    assert!(result.is_err());
    assert!(state.borrow().file.is_empty());
}

#[test]
fn invalid_task_is_rejected_before_password_or_rng_use() {
    let (mut engine, state, calls) = engine(false);
    let mut invalid = task();
    invalid.port = 22;
    assert!(
        engine
            .run(
                &invalid,
                Zeroizing::new(b"pw".to_vec()),
                ClientContribution::new([4; 32]),
                None
            )
            .is_err()
    );
    assert!(!state.borrow().validated);
    assert_eq!(*calls.borrow(), 0);
    assert!(engine.entropy.bytes.borrow().is_empty());
}
