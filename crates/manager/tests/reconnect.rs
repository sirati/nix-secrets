//! The TUI reconnects when its connection to the backend breaks, as when
//! the SSH tunnel to a remote backend hiccups. A request on screen is never
//! answered by the break: it is dropped from the screen, the backend keeps
//! it waiting, and it is shown again from the start once the TUI is
//! attached again. Here a proxy stands for the tunnel and cuts it.
use nix_secrets_core::{Backend, Schema, SecretStore};
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::client::BackendClient;
use nix_secrets_manager::operator_channel::{self, ChannelEvent, Decision, OperatorInput};
use serde_json::json;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TOKEN: &str = "host.services.app.token";

/// Forwards connections on `path` to `backend`; `cut` breaks all of them.
#[derive(Clone)]
struct Tunnel {
    open: Arc<Mutex<Vec<UnixStream>>>,
}

impl Tunnel {
    fn start(backend: PathBuf, path: &Path) -> Self {
        let listener = UnixListener::bind(path).unwrap();
        let tunnel = Self {
            open: Default::default(),
        };
        let open = Arc::clone(&tunnel.open);
        std::thread::spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else { return };
                let Ok(upstream) = UnixStream::connect(&backend) else {
                    continue;
                };
                let mut copies = open.lock().unwrap();
                copies.push(client.try_clone().unwrap());
                copies.push(upstream.try_clone().unwrap());
                for (mut from, mut to) in [
                    (client.try_clone().unwrap(), upstream.try_clone().unwrap()),
                    (upstream, client),
                ] {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut from, &mut to);
                        let _ = to.shutdown(std::net::Shutdown::Both);
                    });
                }
            }
        });
        tunnel
    }

    fn cut(&self) {
        for stream in self.open.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn next_prompt(events: &Receiver<ChannelEvent>) -> operator_channel::SecretPrompt {
    loop {
        match events.recv_timeout(Duration::from_secs(30)).expect("no prompt") {
            ChannelEvent::Prompt(prompt) => return prompt,
            ChannelEvent::Lost(_) => panic!("lost the channel before the prompt"),
            _ => {}
        }
    }
}

#[test]
fn a_broken_channel_never_answers_and_the_request_returns_after_reattaching() {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("id");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&identity)
        .status()
        .unwrap()
        .success());
    let public = std::fs::read_to_string(identity.with_extension("pub")).unwrap();
    let public = public.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let socket = temp.path().join("backend.sock");
    let json = json!({"host": {
        "metadata": {"socketPath": socket,
            "deployment": {"host": "host", "destination": "forward@host", "port": 22}},
        "services": {"app": {"token": {
            "kind": "secret", "description": "API token",
            "recipientPublicKeys": [public], "recipientIds": ["operator"],
            "consumerUnits": [], "valueType": "password",
            "destination": {"path": "/persistent/secrets/app/service/token",
                "category": "service", "owner": "root", "group": "root", "mode": "0400"}
        }}}
    }})
    .to_string();
    let schema = Schema::from_json(&json).unwrap();
    let backend = Backend::bind(
        &socket,
        schema.clone(),
        SecretStore::new(temp.path().join("nix-secrets.toml")),
    )
    .unwrap()
    .with_operator_timing(Duration::from_secs(600), Duration::from_millis(200));
    std::thread::spawn(move || backend.serve());
    BackendClient::new(UnixStream::connect(&socket).unwrap())
        .set(
            &nix_secrets_core::SecretPath::parse(TOKEN).unwrap(),
            b"token-value",
            &[nix_secrets_crypto::Recipient {
                id: "operator",
                ssh_public_key: &public,
            }],
            &AgeCommandProvider::identity_file(&identity),
        )
        .unwrap();
    let tunneled = temp.path().join("tunnel.sock");
    let tunnel = Tunnel::start(socket.clone(), &tunneled);
    let (events, channel) = mpsc::channel();
    let (inputs, incoming) = mpsc::channel::<OperatorInput>();
    let provider = AgeCommandProvider::identity_file(&identity);
    let channel_socket = tunneled.clone();
    std::thread::spawn(move || {
        operator_channel::run_reconnecting(
            &channel_socket,
            &schema,
            &provider,
            "test",
            &events,
            &incoming,
            Duration::from_millis(100),
        )
    });
    let mut requester = Command::new(env!("CARGO_BIN_EXE_nix-secrets"))
        .args(["with-secrets", "--backend-socket"])
        .arg(&socket)
        .args([TOKEN, "--", "true"])
        .env("XDG_RUNTIME_DIR", temp.path())
        .env_remove("NIX_SECRETS_PROCEDURE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let shown = next_prompt(&channel);
    tunnel.cut();
    // The channel reports the loss; the requester still waits.
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        match channel.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(ChannelEvent::Lost(_)) => break,
            Ok(_) => {}
            Err(_) => panic!("the cut was not noticed"),
        }
    }
    // An approval given while disconnected reaches nobody.
    inputs
        .send(
            Decision {
                id: shown.id.clone(),
                approved: true,
            }
            .into(),
        )
        .unwrap();
    assert!(requester.try_wait().unwrap().is_none(), "the cut answered the request");
    // Attached again, the same request is shown from the start.
    let again = next_prompt(&channel);
    assert_eq!(again.id, shown.id);
    assert!(again.deadline.is_some_and(|at| at > Instant::now() + Duration::from_secs(100)));
    inputs
        .send(
            Decision {
                id: again.id.clone(),
                approved: false,
            }
            .into(),
        )
        .unwrap();
    let output = requester.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("the operator denied the secret request"), "{stderr}");
}
