//! Real CLI -> backend -> operator approval -> detached login signer ->
//! client ssh-agent -> signature. The operator approves the logins before
//! the requester's command starts or connects, and only the detached signer
//! talks to the client agent. The test key is generated at runtime in the
//! client fixture only.
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::git::agent::{read_message, write_message};
use nix_secrets_core::secret_request::{is_same_or_descendant, parent_pid};
use nix_secrets_core::ssh_auth::{self, SignatureRequest};
use nix_secrets_core::{Backend, Schema, SecretStore};
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::operator_channel::{self, ChannelEvent, Decision};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

/// The requester's command: it logs in twice, as an update that reconnects
/// does. With `SSH_AUTH_TEST_ON_REQUEST` it first tries without an
/// approval, then asks for one.
#[test]
fn ssh_challenge_child() {
    let Ok(encoded) = std::env::var("SSH_AUTH_TEST_REQUEST") else {
        return;
    };
    std::fs::write(std::env::var_os("SSH_AUTH_TEST_STARTED").unwrap(), b"").unwrap();
    let request: SignatureRequest =
        serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
    let sign = || {
        let mut socket =
            UnixStream::connect(std::env::var_os("SSH_AUTH_SOCK").unwrap()).unwrap();
        write_message(&mut socket, &[11]).unwrap();
        assert_eq!(
            read_message(&mut socket).unwrap().unwrap(),
            ssh_auth::identities(&request.public_key).unwrap()
        );
        write_message(&mut socket, &request.message).unwrap();
        read_message(&mut socket).unwrap().unwrap()
    };
    if let Some(program) = std::env::var_os("SSH_AUTH_TEST_ON_REQUEST") {
        // Nothing signs before the operator approved.
        assert_eq!(sign(), [5]);
        assert!(Command::new(program)
            .arg("approve-ssh-login")
            .status()
            .unwrap()
            .success());
    }
    let mut replies = Vec::new();
    for _ in 0..2 {
        let reply = sign();
        if std::env::var_os("SSH_AUTH_TEST_REFUSED").is_some() {
            assert_eq!(reply, [5]);
        } else {
            ssh_auth::validate_reply(&reply).unwrap();
        }
        replies.push(reply);
    }
    assert_eq!(replies[0], replies[1]);
    std::fs::write(
        std::env::var_os("SSH_AUTH_TEST_REPLY").unwrap(),
        &replies[0],
    )
    .unwrap();
}

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Who asked the client agent to sign: the process and its ancestors, read
/// when it connected. Listing the keys, which asks 1Password nothing, is
/// not recorded.
type Callers = Arc<Mutex<Vec<Vec<u32>>>>;

/// Whether `pid` runs: it exists and is no zombie.
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| stat.rsplit_once(')').map(|(_, rest)| rest.trim_start().starts_with('Z')))
        .is_some_and(|zombie| !zombie)
}

fn ancestry(pid: u32) -> Vec<u32> {
    let mut chain = vec![pid];
    while let Some(parent) = parent_pid(*chain.last().unwrap()).filter(|parent| *parent > 1) {
        chain.push(parent);
    }
    chain
}

/// A client agent that records each caller and relays to `agent`, as
/// 1Password would see its callers.
fn recording_agent(socket: &Path, agent: PathBuf) -> Callers {
    let listener = UnixListener::bind(socket).unwrap();
    let callers = Callers::default();
    let recorded = callers.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let peer = rustix::net::sockopt::socket_peercred(&stream).unwrap();
            let caller = ancestry(peer.pid.as_raw_nonzero().get() as u32);
            let mut upstream = UnixStream::connect(&agent).unwrap();
            while let Ok(Some(message)) = read_message(&mut stream) {
                if message.first() != Some(&11) {
                    recorded.lock().unwrap().push(caller.clone());
                }
                write_message(&mut upstream, &message).unwrap();
                let reply = read_message(&mut upstream).unwrap().unwrap();
                write_message(&mut stream, &reply).unwrap();
            }
        }
    });
    callers
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Approve,
    Deny,
    WrongUser,
    HostBound,
    OnRequest,
}

fn exercise(mode: Mode) {
    nix_secrets_manager::login_signer::set_program(env!("CARGO_BIN_EXE_nix-secrets").into());
    let approve = mode != Mode::Deny;
    let wrong_user = mode == Mode::WrongUser;
    let host_bound = mode == Mode::HostBound;
    let temp = tempfile::tempdir().unwrap();
    let client = temp.path().join("client");
    let backend = temp.path().join("backend");
    for directory in [&client, &backend] {
        std::fs::create_dir(directory).unwrap();
    }
    let key = client.join("key");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap()
        .success());
    let public_file = key.with_extension("pub");
    let public_key = std::fs::read_to_string(&public_file).unwrap();
    let agent_socket = client.join("agent.sock");
    let _agent = Agent(
        Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&agent_socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if agent_socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(Command::new("ssh-add")
        .arg(&key)
        .env("SSH_AUTH_SOCK", &agent_socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    let recording_socket = client.join("recording.sock");
    let callers = recording_agent(&recording_socket, agent_socket.clone());
    let schema = Schema::from_json("{}").unwrap();
    let backend_socket = backend.join("backend.sock");
    let server = Backend::bind(
        &backend_socket,
        schema.clone(),
        SecretStore::new(backend.join("secrets.toml")),
    )
    .unwrap();
    std::thread::spawn(move || server.serve());
    let (events, incoming) = mpsc::channel();
    let (decisions, answers) = mpsc::channel();
    let socket = backend_socket.clone();
    let signing_agent = recording_socket.clone();
    std::thread::spawn(move || {
        // This provider cannot decrypt anything. SSH authentication must not use it.
        let provider =
            AgeCommandProvider::identity_file(PathBuf::from("/nonexistent/test-identity"));
        let _ = operator_channel::run_with_agent(
            &socket,
            &schema,
            &provider,
            "test client",
            &events,
            &answers,
            Some(&signing_agent),
        );
    });
    assert!(matches!(
        incoming.recv_timeout(Duration::from_secs(5)).unwrap(),
        ChannelEvent::Attached
    ));
    let blob = ssh_auth::key_blob(&public_key).unwrap();
    let mut data = Vec::new();
    ssh_auth::put_string(&mut data, &[17; 32]);
    data.push(50);
    for part in [
        if wrong_user {
            b"root".as_slice()
        } else {
            b"update".as_slice()
        },
        b"ssh-connection",
        if host_bound {
            b"publickey-hostbound-v00@openssh.com".as_slice()
        } else {
            b"publickey".as_slice()
        },
    ] {
        ssh_auth::put_string(&mut data, part);
    }
    data.push(1);
    ssh_auth::put_string(&mut data, b"ssh-ed25519");
    ssh_auth::put_string(&mut data, &blob);
    if host_bound {
        ssh_auth::put_string(&mut data, &blob);
    }
    let mut message = vec![13];
    ssh_auth::put_string(&mut message, &blob);
    ssh_auth::put_string(&mut message, &data);
    message.extend_from_slice(&[0; 4]);
    let request = SignatureRequest {
        public_key,
        destination: "update@ns1.lamk.eu".into(),
        message,
    };
    // Ed25519 is deterministic: the real agent's signature, asked directly.
    let expected = (approve && !wrong_user).then(|| ssh_auth::sign(&agent_socket, &request).unwrap());
    let reply_file = backend.join("reply");
    let started = backend.join("started");
    let runtime = backend.join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_nix-secrets"));
    command.args(["with-ssh-agent", "--public-key"]).arg(&public_file);
    if mode == Mode::OnRequest {
        command.arg("--approve-on-request").env(
            "SSH_AUTH_TEST_ON_REQUEST",
            env!("CARGO_BIN_EXE_nix-secrets"),
        );
    }
    command
        .args([
            "--destination",
            "update@ns1.lamk.eu",
            "--reason",
            "Upload the approved signed ns1 generation.",
            "--backend-socket",
        ])
        .arg(&backend_socket)
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "ssh_challenge_child", "--nocapture"])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env(
            "SSH_AUTH_TEST_REQUEST",
            STANDARD.encode(serde_json::to_vec(&request).unwrap()),
        )
        .env("SSH_AUTH_TEST_REPLY", &reply_file)
        .env("SSH_AUTH_TEST_STARTED", &started)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !approve || wrong_user {
        command.env("SSH_AUTH_TEST_REFUSED", "1");
    }
    let child = command.spawn().unwrap();
    let prompt = match incoming.recv_timeout(Duration::from_secs(10)).unwrap() {
        ChannelEvent::Prompt(prompt) => prompt,
        _ => panic!("missing SSH login approval prompt"),
    };
    assert!(prompt.ssh_signature && prompt.ssh_login);
    assert_eq!(prompt.values[0].identifier, "update@ns1.lamk.eu");
    assert_eq!(
        prompt.reason.as_deref(),
        Some("Upload the approved signed ns1 generation.")
    );
    assert_eq!(prompt.requester.pid, child.id());
    assert!(prompt.values[0]
        .description
        .as_ref()
        .unwrap()
        .contains("cannot be verified"));
    // The operator takes a while; the command has not started, or with
    // --approve-on-request it waits for the approval before connecting.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(started.exists(), mode == Mode::OnRequest);
    assert!(!reply_file.exists());
    assert!(callers.lock().unwrap().is_empty(), "the agent was asked before the approval");
    decisions
        .send(
            Decision {
                id: prompt.id.clone(),
                approved: approve,
            }
            .into(),
        )
        .unwrap();
    match incoming.recv_timeout(Duration::from_secs(10)).unwrap() {
        ChannelEvent::SignatureFinished { result, .. } => assert_eq!(result.is_ok(), approve),
        _ => panic!("missing login approval result"),
    }
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !approve {
        // Denied: the command never ran and nothing signed.
        assert!(!output.status.success());
        assert!(stderr.contains("denied"), "{stderr}");
        assert!(!started.exists());
        assert!(callers.lock().unwrap().is_empty());
    } else {
        assert!(output.status.success(), "{stderr}");
        assert_eq!(
            std::fs::read(&reply_file).unwrap(),
            expected.unwrap_or_else(|| vec![5])
        );
        // Nothing asked the operator again for the second login.
        assert!(incoming.recv_timeout(Duration::from_millis(200)).is_err() || wrong_user);
        // Only the detached signer talked to the client agent: never this
        // process (the TUI), and nothing below it.
        let tui = std::process::id();
        let callers = callers.lock().unwrap();
        let expected_calls = if wrong_user { 1 } else { 3 };
        assert_eq!(callers.len(), expected_calls, "{callers:?}");
        for chain in callers.iter() {
            assert!(!chain.contains(&tui), "the TUI is an ancestor of {chain:?}");
            assert!(!is_same_or_descendant(chain[0], tui));
            assert_ne!(parent_pid(chain[0]), Some(tui));
        }
        assert!(callers.iter().all(|chain| chain[0] == callers[0][0]));
    }
    let signer = callers.lock().unwrap().first().map(|chain| chain[0]);
    // The approval ended with the requester's connection; its signer exits.
    for _ in 0..200 {
        if operator_channel::grant_signer_pid(&prompt.id).is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(operator_channel::grant_signer_pid(&prompt.id).is_none());
    if let Some(signer) = signer {
        for _ in 0..500 {
            if !alive(signer) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive(signer), "the login signer outlived its approval");
    }
    assert_eq!(std::fs::read_dir(runtime).unwrap().count(), 0);
    assert!(!backend.join("secrets.toml").exists());
}

#[test]
fn approved_logins_return_only_the_real_client_signature() {
    exercise(Mode::Approve);
}
#[test]
fn denied_logins_never_start_the_command() {
    exercise(Mode::Deny);
}
#[test]
fn a_different_login_user_is_never_signed() {
    exercise(Mode::WrongUser);
}
#[test]
fn host_bound_logins_return_only_the_real_client_signature() {
    exercise(Mode::HostBound);
}
#[test]
fn a_command_asks_for_the_approval_before_it_connects() {
    exercise(Mode::OnRequest);
}
