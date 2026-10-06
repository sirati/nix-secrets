//! A requester may start the backend itself and register its request
//! before any TUI exists. The request then waits, without any countdown,
//! until an operator attaches; the TUI uses the backend's evaluation
//! instead of evaluating the repository again.
use nix_secrets_core::{Backend, Schema, SecretStore};
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::client::BackendClient;
use nix_secrets_manager::command::CommandSpec;
use nix_secrets_manager::operator_channel::{self, ChannelEvent, Decision};
use nix_secrets_manager::startup::{self, Launcher};
use nix_secrets_manager::with_secrets::{connect_or_start_backend, Options};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const TOKEN: &str = "host.services.app.token";

fn document(socket: &Path, public: &str) -> String {
    json!({"host": {
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
    .to_string()
}

/// Starts the backend in this process, as `nix run REPO#secrets-backend`
/// would in another, on the socket the command names.
struct InProcess {
    repository: PathBuf,
    public: String,
    deadline: Duration,
    starts: usize,
}

impl Launcher for InProcess {
    type Guard = ();
    fn start(&mut self, command: &CommandSpec) -> std::io::Result<()> {
        self.starts += 1;
        let socket = command
            .arguments
            .windows(2)
            .find(|pair| pair[0] == "--socket")
            .map(|pair| PathBuf::from(&pair[1]))
            .expect("the backend command names its socket");
        let json = document(&socket, &self.public);
        let backend = Backend::bind(
            &socket,
            Schema::from_json(&json).unwrap(),
            SecretStore::new(self.repository.join("nix-secrets.toml")),
        )?
        .with_schema_document(json)
        .with_operator_timing(self.deadline, Duration::from_millis(200));
        std::thread::spawn(move || backend.serve());
        Ok(())
    }
}

#[test]
fn a_request_registered_before_any_tui_waits_and_reaches_the_first_one_that_attaches() {
    let temp = tempfile::tempdir().unwrap();
    let repository = temp.path().join("repository");
    std::fs::create_dir(&repository).unwrap();
    let runtime = temp.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let identity = temp.path().join("id");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&identity)
        .status()
        .unwrap()
        .success());
    let public = std::fs::read_to_string(identity.with_extension("pub")).unwrap();
    let public = public.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let deadline = Duration::from_secs(2);
    let mut launcher = InProcess {
        repository: repository.clone(),
        public: public.clone(),
        deadline,
        starts: 0,
    };
    let options = Options {
        repository: repository.clone(),
        ..Options::default()
    };
    // No backend runs: the requester starts it, on the TUI's socket name.
    let stream = connect_or_start_backend(&options, &runtime, &mut launcher).unwrap();
    assert_eq!(launcher.starts, 1);
    let socket = runtime
        .join("nix-secrets")
        .join(startup::socket_name(&std::fs::canonicalize(&repository).unwrap()));
    assert!(socket.exists());
    // A second requester finds the same backend instead of starting one.
    drop(connect_or_start_backend(&options, &runtime, &mut launcher).unwrap());
    assert_eq!(launcher.starts, 1);
    let mut client = BackendClient::new(stream);
    client
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
    // The request is registered while no TUI is attached.
    let child = Command::new(env!("CARGO_BIN_EXE_nix-secrets"))
        .args(["with-secrets", "--repository"])
        .arg(&repository)
        .args([TOKEN, "--", "true"])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env_remove("NIX_SECRETS_PROCEDURE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(30);
    let (json, _, waiting) = loop {
        let state = client.schema_document().unwrap();
        if state.2 || Instant::now() > until {
            break state;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(waiting, "the request waits for an operator");
    // Waiting longer than a shown request's deadline costs it nothing.
    std::thread::sleep(deadline * 2);
    // The TUI takes the backend's evaluation rather than evaluating again,
    // even though it is older than a fresh one.
    let json = startup::reuse_backend_schema(json, startup::FRESH_EVALUATION * 2, waiting)
        .expect("a waiting request makes the TUI use the backend's evaluation");
    let schema = Schema::from_json(&json).unwrap();
    let (events, channel) = mpsc::channel();
    let (inputs, incoming) = mpsc::channel();
    let provider = AgeCommandProvider::identity_file(&identity);
    std::thread::spawn(move || {
        let _ = operator_channel::run(&socket, &schema, &provider, "test", &events, &incoming);
    });
    let prompt = loop {
        match channel.recv_timeout(Duration::from_secs(30)).unwrap() {
            ChannelEvent::Prompt(prompt) => break prompt,
            _ => {}
        }
    };
    // Its countdown starts now that it is shown.
    assert!(prompt
        .deadline
        .is_some_and(|at| at > Instant::now() + Duration::from_secs(100)));
    inputs
        .send(
            Decision {
                id: prompt.id,
                approved: false,
            }
            .into(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no nix-secrets TUI is attached yet; waiting"),
        "{stderr}"
    );
    assert!(stderr.contains("the operator denied the secret request"), "{stderr}");
    // A plain old evaluation without waiting requests is evaluated afresh.
    assert!(startup::reuse_backend_schema(Some("{}".into()), startup::FRESH_EVALUATION * 2, false)
        .is_none());
}
