//! Secret requests from the backend host: `with-secrets` asks the attached
//! TUI, the operator approves once, the TUI decrypts the whole batch with
//! one 1Password authorization, and the command reads the values through
//! `pipe-secret` from a private session socket that is gone afterwards.
//!
//! The TUI end is the real operator channel with a provider that runs real
//! `age` through the real `nix-secrets-1password` launcher; `op` is a fake
//! that logs every call, so one authorization is exactly one logged call.

use nix_secrets_core::{Backend, Schema, SecretStore};
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::client::BackendClient;
use nix_secrets_manager::controller::Controller;
use nix_secrets_manager::keypair::{self, Keypair};
use nix_secrets_manager::operator_channel::{self, ChannelEvent, Decision};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

const KEY: &str = "host.services.signing.generation-key";
const TOKEN: &str = "host.services.signing.token";
const OTHER: &str = "host.services.signing.other";

/// Different bytes for each key, so a mix-up shows.
fn fake_generator(_: &nix_secrets_core::KeypairGenerator) -> Result<Keypair, String> {
    keypair::run(&[
        "sh".into(),
        "-c".into(),
        "printf 'NMBLSK01\\0private-bytes'; printf 'public' >&3".into(),
    ])
}

struct Fixture {
    temp: tempfile::TempDir,
    schema: Schema,
    document: serde_json::Value,
    socket: PathBuf,
    identity: PathBuf,
    runtime: PathBuf,
    bin: PathBuf,
}

/// Holds one test at a time: parallel forks copy script descriptors that
/// are still open for writing, and executing them then fails with ETXTBSY.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("id");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&identity)
        .status()
        .unwrap()
        .success());
    let public = std::fs::read_to_string(identity.with_extension("pub")).unwrap();
    let public = public
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let socket = temp.path().join("backend.sock");
    let secret = |description: &str| {
        json!({
            "kind": "secret", "description": description,
            "recipientPublicKeys": [public], "recipientIds": ["operator"],
            "consumerUnits": [], "valueType": "password",
            "destination": {"path": "/persistent/secrets/signing/service/x",
                "category": "service", "owner": "root", "group": "root", "mode": "0400"}
        })
    };
    let document = json!({"host": {
        "metadata": {"socketPath": socket,
            "deployment": {"host": "host", "destination": "forward@host", "port": 22}},
        "services": {"signing": {
            "generation-key": {
                "kind": "operator", "description": "NMBL generation signing key",
                "recipientPublicKeys": [public], "recipientIds": ["operator"],
                "generator": {"installable": "nmbl#nmbl-sign", "args": ["keygen"]}
            },
            "token": secret("API token"),
            "other": secret("not requested"),
        }}
    }});
    let schema = Schema::from_json(&document.to_string()).unwrap();
    let backend = Backend::bind(
        &socket,
        schema.clone(),
        SecretStore::new(temp.path().join("nix-secrets.toml")),
    )
    .unwrap();
    std::thread::spawn(move || backend.serve());
    let runtime = temp.path().join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    // `op` logs each call; the launcher's authorization is one call.
    let op = bin.join(".op.tmp");
    std::fs::write(
        &op,
        format!(
            "#!/bin/sh\necho \"$*\" >> {}\nexit 0\n",
            temp.path().join("op-calls").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&op, bin.join("op")).unwrap();
    let fixture = Fixture {
        temp,
        schema,
        document,
        socket,
        identity,
        runtime,
        bin,
    };
    let mut controller = fixture.controller();
    controller.generate_keypair(KEY).unwrap();
    use nix_secrets_manager::ui::SecretWriter;
    controller
        .write(TOKEN, zeroize::Zeroizing::new(b"token-value".to_vec()))
        .map_err(|(error, _)| error)
        .unwrap();
    controller
        .write(OTHER, zeroize::Zeroizing::new(b"other-value".to_vec()))
        .map_err(|(error, _)| error)
        .unwrap();
    fixture
}

/// The TUI's operator channel on a thread, answering with `decide`.
struct Operator {
    events: Receiver<ChannelEvent>,
    decisions: Sender<Decision>,
}

impl Fixture {
    fn controller(&self) -> Controller {
        let stream = std::os::unix::net::UnixStream::connect(&self.socket).unwrap();
        Controller::new(
            BackendClient::new(stream),
            self.schema.clone(),
            AgeCommandProvider::identity_file(&self.identity),
            vec![],
        )
        .unwrap()
        .with_keypair_runner(fake_generator)
    }

    /// Real age through the real launcher, which asks the fake `op` once. A
    /// wrapper puts the fake first in the launcher's PATH only.
    fn provider(&self) -> AgeCommandProvider {
        let wrapper = self.bin.join("launcher");
        let staging = self.bin.join(".launcher.tmp");
        std::fs::write(
            &staging,
            format!(
                "#!/bin/sh\nPATH='{}':\"$PATH\" exec '{}' \"$@\"\n",
                self.bin.display(),
                env!("CARGO_BIN_EXE_nix-secrets-1password")
            ),
        )
        .unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&staging, &wrapper).unwrap();
        AgeCommandProvider::identity_file(&self.identity).through(wrapper, vec![])
    }

    fn attach(&self) -> Operator {
        let (events, channel) = mpsc::channel();
        let (decisions, incoming) = mpsc::channel();
        let socket = self.socket.clone();
        let schema = self.schema.clone();
        let provider = self.provider();
        std::thread::spawn(move || {
            let _ = operator_channel::run(
                &socket,
                &schema,
                &provider,
                "test identity",
                &events,
                &incoming,
            );
        });
        let operator = Operator {
            events: channel,
            decisions,
        };
        match operator.next() {
            ChannelEvent::Attached => {}
            _ => panic!("the channel did not attach"),
        }
        operator
    }

    fn op_calls(&self) -> usize {
        std::fs::read_to_string(self.temp.path().join("op-calls"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    /// `nix-secrets with-secrets IDENTIFIERS -- sh -c SCRIPT` in the background.
    fn with_secrets(&self, identifiers: &[&str], script: &str) -> std::process::Child {
        Command::new(env!("CARGO_BIN_EXE_nix-secrets"))
            .arg("with-secrets")
            .args(["--reason", "Sign the requested ns1 boot generation."])
            .arg("--backend-socket")
            .arg(&self.socket)
            .args(identifiers)
            .args(["--", "sh", "-c", script])
            .env("NIX_SECRETS", env!("CARGO_BIN_EXE_nix-secrets"))
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("OUT", self.temp.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn sessions(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.runtime)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect()
    }
}

impl Operator {
    fn next(&self) -> ChannelEvent {
        self.events
            .recv_timeout(Duration::from_secs(60))
            .expect("the operator channel sent nothing")
    }

    fn prompt(&self) -> operator_channel::SecretPrompt {
        match self.next() {
            ChannelEvent::Prompt(prompt) => prompt,
            _ => panic!("expected a prompt"),
        }
    }

    fn decide(&self, prompt: &operator_channel::SecretPrompt, approved: bool) {
        self.decisions
            .send(Decision {
                id: prompt.id.clone(),
                approved,
            })
            .unwrap();
    }
}

fn finish(child: std::process::Child) -> Output {
    child.wait_with_output().unwrap()
}

/// Reads both values with pipe-secret, asks for one outside the batch, and
/// records the session socket.
const SCRIPT: &str = r#"
"$NIX_SECRETS" pipe-secret host.services.signing.generation-key > "$OUT/key" || exit 10
"$NIX_SECRETS" pipe-secret host.services.signing.token -- sh -c 'cat > "$OUT/token"' || exit 11
if "$NIX_SECRETS" pipe-secret host.services.signing.other > "$OUT/other" 2> "$OUT/refusal"; then exit 12; fi
printf '%s' "$NIX_SECRETS_SESSION" > "$OUT/session"
exit 7
"#;

#[test]
fn an_approved_batch_reaches_the_command_with_one_authorization() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = fixture();
    let operator = fixture.attach();
    let child = fixture.with_secrets(&[KEY, TOKEN], SCRIPT);
    let prompt = operator.prompt();
    // The modal shows every value, its kind and description, the recipient
    // key, the provider, and who asked, as read by the backend from /proc.
    let identifiers = prompt
        .values
        .iter()
        .map(|value| value.identifier.as_str())
        .collect::<Vec<_>>();
    assert_eq!(identifiers, [KEY, TOKEN]);
    assert_eq!(prompt.values[0].kind, "operator key");
    assert_eq!(
        prompt.values[0].description.as_deref(),
        Some("NMBL generation signing key")
    );
    let recipient = &prompt.values[1].recipients[0];
    assert!(
        recipient.starts_with("operator ") && recipient.contains(": ssh-ed25519 SHA256:"),
        "{recipient}"
    );
    assert_eq!(prompt.identity, "test identity");
    assert_eq!(prompt.requester.pid, child.id());
    assert_eq!(
        prompt.reason.as_deref(),
        Some("Sign the requested ns1 boot generation.")
    );
    assert!(prompt
        .requester
        .argv
        .iter()
        .any(|argument| argument == "with-secrets"));
    assert!(prompt.requester.cwd.is_some());
    assert!(prompt.parent.is_some());
    assert_eq!(
        fixture.op_calls(),
        0,
        "nothing is decrypted before approval"
    );
    operator.decide(&prompt, true);
    match operator.next() {
        ChannelEvent::Finished { result, .. } => assert_eq!(result, Ok(2)),
        _ => panic!("expected the request to finish"),
    }
    let output = finish(child);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let out = fixture.temp.path();
    assert_eq!(
        std::fs::read(out.join("key")).unwrap(),
        b"NMBLSK01\0private-bytes"
    );
    assert_eq!(std::fs::read(out.join("token")).unwrap(), b"token-value");
    assert!(std::fs::read(out.join("other")).unwrap().is_empty());
    let refusal = std::fs::read_to_string(out.join("refusal")).unwrap();
    assert!(
        refusal.contains("not part of the approved request"),
        "{refusal}"
    );
    assert_eq!(
        fixture.op_calls(),
        1,
        "one 1Password authorization for the batch"
    );
    // The session socket is gone once the command exits.
    let session = PathBuf::from(std::fs::read_to_string(out.join("session")).unwrap());
    // The backend runs in this test process, so the session lives in its
    // runtime directory, inside a private directory of its own.
    assert!(session
        .parent()
        .and_then(|directory| directory.file_name())
        .is_some_and(|name| name.to_string_lossy().starts_with("nix-secrets-session-")));
    assert!(!session.parent().unwrap().exists());
    assert!(!session.exists());
}

#[test]
fn a_denied_request_never_runs_the_command() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = fixture();
    let operator = fixture.attach();
    let marker = fixture.temp.path().join("ran");
    let child = fixture.with_secrets(&[TOKEN], &format!("touch '{}'", marker.display()));
    let prompt = operator.prompt();
    operator.decide(&prompt, false);
    match operator.next() {
        ChannelEvent::Finished { result, .. } => assert!(result.is_err()),
        _ => panic!("expected the request to finish"),
    }
    let output = finish(child);
    assert!(!output.status.success());
    assert!(!marker.exists(), "the command ran after a denial");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("denied"),
        "{output:?}"
    );
    assert_eq!(fixture.op_calls(), 0, "nothing was decrypted");
    assert!(fixture.sessions().is_empty());
}

#[test]
fn without_an_attached_tui_the_request_fails_clearly() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = fixture();
    let marker = fixture.temp.path().join("ran");
    let output = finish(fixture.with_secrets(&[TOKEN], &format!("touch '{}'", marker.display())));
    assert!(!output.status.success());
    assert!(!marker.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("open the nix-secrets TUI and retry"),
        "{stderr}"
    );
    assert_eq!(fixture.op_calls(), 0, "never decrypted anywhere else");
    // pipe-secret on its own, outside a session, goes the same way.
    let output = Command::new(env!("CARGO_BIN_EXE_nix-secrets"))
        .args(["pipe-secret", "--backend-socket"])
        .arg(&fixture.socket)
        .arg(TOKEN)
        .env_remove("NIX_SECRETS_SESSION")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("open the nix-secrets TUI and retry"));
}

#[test]
fn pipe_secret_alone_is_a_one_value_request_to_the_tui() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = fixture();
    let operator = fixture.attach();
    let child = Command::new(env!("CARGO_BIN_EXE_nix-secrets"))
        .args(["pipe-secret", "--backend-socket"])
        .arg(&fixture.socket)
        .arg(TOKEN)
        .env_remove("NIX_SECRETS_SESSION")
        .env("XDG_RUNTIME_DIR", &fixture.runtime)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let prompt = operator.prompt();
    assert_eq!(prompt.values.len(), 1);
    operator.decide(&prompt, true);
    let output = finish(child);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"token-value");
    assert_eq!(fixture.op_calls(), 1);
    assert!(fixture.sessions().is_empty());
}

#[test]
fn a_second_request_waits_for_none_and_unset_values_are_refused_unasked() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = fixture();
    let operator = fixture.attach();
    let first = fixture.with_secrets(&[TOKEN], "exit 0");
    let prompt = operator.prompt();
    // Only one request may wait for the operator.
    let second = finish(fixture.with_secrets(&[KEY], "exit 0"));
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("another secret request"));
    operator.decide(&prompt, false);
    let _ = operator.next();
    assert!(!finish(first).status.success());
    // A value that is not declared is refused before the operator is asked.
    let output = finish(fixture.with_secrets(&["host.services.signing.missing"], "exit 0"));
    assert!(!output.status.success());
    match operator.next() {
        ChannelEvent::Finished {
            result: Err(reason),
            ..
        } => {
            assert!(reason.contains("refused"), "{reason}")
        }
        _ => panic!("expected a refusal without a prompt"),
    }
}

#[test]
fn local_mode_decrypts_here_with_one_authorization() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = fixture();
    let schema_file = fixture.temp.path().join("schema.json");
    // Local mode reads the schema from a file with --backend-socket.

    std::fs::write(&schema_file, fixture.document.to_string()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nix-secrets"))
        .args(["with-secrets", "--local", "--backend-socket"])
        .arg(&fixture.socket)
        .arg("--schema-file")
        .arg(&schema_file)
        .arg("--secret-identity")
        .arg(&fixture.identity)
        .args([KEY, TOKEN, "--", "sh", "-c", SCRIPT])
        .env("NIX_SECRETS", env!("CARGO_BIN_EXE_nix-secrets"))
        .env("XDG_RUNTIME_DIR", &fixture.runtime)
        .env("OUT", fixture.temp.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert_eq!(
        std::fs::read(fixture.temp.path().join("token")).unwrap(),
        b"token-value"
    );
    assert!(fixture.sessions().is_empty());
}
