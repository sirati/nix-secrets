//! Real CLI -> backend -> operator approval -> client ssh-agent -> signature.
//! The test key is generated at runtime in the client fixture only.
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::git::agent::{read_message, write_message};
use nix_secrets_core::ssh_auth::{self, SignatureRequest};
use nix_secrets_core::{Backend, Schema, SecretStore};
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::operator_channel::{self, ChannelEvent, Decision};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn ssh_challenge_child() {
    let Ok(encoded) = std::env::var("SSH_AUTH_TEST_REQUEST") else {
        return;
    };
    let request: SignatureRequest =
        serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
    let mut socket = UnixStream::connect(std::env::var_os("SSH_AUTH_SOCK").unwrap()).unwrap();
    write_message(&mut socket, &[11]).unwrap();
    assert_eq!(
        read_message(&mut socket).unwrap().unwrap(),
        ssh_auth::identities(&request.public_key).unwrap()
    );
    write_message(&mut socket, &request.message).unwrap();
    let reply = read_message(&mut socket).unwrap().unwrap();
    if std::env::var_os("SSH_AUTH_TEST_REFUSED").is_some() {
        assert_eq!(reply, [5]);
    } else {
        ssh_auth::validate_reply(&reply).unwrap();
    }
    std::fs::write(std::env::var_os("SSH_AUTH_TEST_REPLY").unwrap(), reply).unwrap();
}

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn exercise(approve: bool, wrong_user: bool, host_bound: bool) {
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
    let signing_agent = agent_socket.clone();
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
    let expected = if approve && !wrong_user {
        Some(ssh_auth::sign(&agent_socket, &request).unwrap())
    } else {
        None
    };
    let reply_file = backend.join("reply");
    let runtime = backend.join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_nix-secrets"));
    command
        .args(["with-ssh-agent", "--public-key"])
        .arg(&public_file)
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !approve || wrong_user {
        command.env("SSH_AUTH_TEST_REFUSED", "1");
    }
    let child = command.spawn().unwrap();
    if wrong_user {
        assert!(incoming.recv_timeout(Duration::from_millis(200)).is_err());
    } else {
        let prompt = match incoming.recv_timeout(Duration::from_secs(5)).unwrap() {
            ChannelEvent::Prompt(prompt) => prompt,
            _ => panic!("missing SSH prompt"),
        };
        assert!(prompt.ssh_signature);
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
        decisions
            .send(Decision {
                id: prompt.id,
                approved: approve,
            })
            .unwrap();
        match incoming.recv_timeout(Duration::from_secs(5)).unwrap() {
            ChannelEvent::SignatureFinished { result, .. } => assert_eq!(result.is_ok(), approve),
            _ => panic!("missing signature result"),
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&reply_file).unwrap(),
        expected.unwrap_or_else(|| vec![5])
    );
    assert_eq!(std::fs::read_dir(runtime).unwrap().count(), 0);
    assert!(!backend.join("secrets.toml").exists());
}

#[test]
fn approved_authentication_returns_only_the_real_client_signature() {
    exercise(true, false, false);
}
#[test]
fn denied_authentication_returns_no_signature() {
    exercise(false, false, false);
}
#[test]
fn a_different_login_user_never_reaches_the_tui() {
    exercise(true, true, false);
}

#[test]
fn host_bound_authentication_returns_only_the_real_client_signature() {
    exercise(true, false, true);
}
