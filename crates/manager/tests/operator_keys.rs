//! Operator-only keys: generated through a declared generator, stored
//! encrypted with a plain public key, never deployed, and handed to other
//! programs only through `pipe-secret`.

use nix_secrets_core::{ApprovalRequest, Backend, Schema, SecretStore};
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::client::BackendClient;
use nix_secrets_manager::controller::Controller;
use nix_secrets_manager::keypair::{self, Keypair};
use nix_secrets_manager::ui::SecretWriter;
use serde_json::json;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const IDENTIFIER: &str = "host.services.signing.generation-key";

/// A generator obeying the contract: fixed private bytes on stdout and a
/// fixed public key on descriptor 3. Deterministic so tests can check bytes.
fn fake_generator(_: &nix_secrets_core::KeypairGenerator) -> Result<Keypair, String> {
    keypair::run(&[
        "sh".into(),
        "-c".into(),
        "printf 'NMBLSK01\\0\\001private-bytes' ; printf '\\001\\002public-raw\\377' >&3".into(),
    ])
}

struct Fixture {
    temp: tempfile::TempDir,
    schema: Schema,
    schema_file: PathBuf,
    socket: PathBuf,
    identity: PathBuf,
}

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
    let document = json!({"host": {
        "metadata": {"socketPath": socket,
            "deployment": {"host": "host", "destination": "forward@host", "port": 22}},
        "services": {"signing": {
            "generation-key": {
                "kind": "operator", "recipientPublicKeys": [public], "recipientIds": ["operator"],
                "generator": {"installable": "github:sirati/siratis-nmbl-bootloader?dir=sirati-nmbl/nmbl-init-rs#nmbl-sign",
                    "args": ["keygen", "--alg", "ml-dsa-65", "--stdio"]}
            },
            "token": {
                "kind": "secret", "recipientPublicKeys": [public], "recipientIds": ["operator"],
                "consumerUnits": [], "valueType": "password",
                "destination": {"path": "/persistent/secrets/signing/service/token",
                    "category": "service", "owner": "root", "group": "root", "mode": "0400"}
            }
        }}
    }});
    let schema = Schema::from_json(&document.to_string()).unwrap();
    let schema_file = temp.path().join("schema.json");
    std::fs::write(&schema_file, document.to_string()).unwrap();
    let backend = Backend::bind(
        &socket,
        schema.clone(),
        SecretStore::new(temp.path().join("nix-secrets.toml")),
    )
    .unwrap();
    std::thread::spawn(move || backend.serve());
    Fixture {
        temp,
        schema,
        schema_file,
        socket,
        identity,
    }
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

    fn pipe_secret(&self, extra: &[&str], stdout: Stdio) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nix-secrets"));
        command
            .arg("pipe-secret")
            .arg("--secret-identity")
            .arg(&self.identity)
            .arg("--backend-socket")
            .arg(&self.socket)
            .arg("--schema-file")
            .arg(&self.schema_file)
            .args(extra)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::piped());
        command.spawn().unwrap().wait_with_output().unwrap()
    }

    fn store(&self) -> String {
        std::fs::read_to_string(self.temp.path().join("nix-secrets.toml")).unwrap()
    }
}

#[test]
fn generated_keypair_round_trips_with_a_plain_public_key() {
    let fixture = fixture();
    let mut controller = fixture.controller();
    controller.generate_keypair(IDENTIFIER).unwrap();
    // The private key decrypts to exactly the generator's stdout.
    assert_eq!(
        controller.reveal_secret(IDENTIFIER).unwrap().as_slice(),
        b"NMBLSK01\0\x01private-bytes"
    );
    // The public key is readable from the store without any decryption,
    // which is how the Nix helper `operatorPublicKey` reads it.
    let document: toml::Value = toml::from_str(&fixture.store()).unwrap();
    let public = document["secrets"][IDENTIFIER]["public_key"]
        .as_str()
        .unwrap();
    use base64::Engine;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(public)
            .unwrap(),
        b"\x01\x02public-raw\xff"
    );
    assert!(!fixture.store().contains("private-bytes"));
    // The row is an operator row that can be generated and copied.
    let row = controller
        .rows()
        .unwrap()
        .into_iter()
        .find(|row| row.path.as_deref() == Some(IDENTIFIER))
        .unwrap();
    assert!(row.is_set && row.can_generate && row.can_copy_public);
    assert_eq!(
        row.category,
        nix_secrets_manager::tree::RowCategory::Operator
    );
    // Password generation does not apply to operator keys.
    assert!(SecretWriter::generate(
        &mut controller,
        IDENTIFIER,
        nix_secrets_manager::ui::GenerateKind::Password
    )
    .is_err());
}

#[test]
fn operator_keys_are_never_deployed() {
    let fixture = fixture();
    let mut controller = fixture.controller();
    controller.generate_keypair(IDENTIFIER).unwrap();
    // Even a request naming the key directly is refused before any SSH.
    let mut client =
        BackendClient::new(std::os::unix::net::UnixStream::connect(&fixture.socket).unwrap());
    client
        .submit_approval(ApprovalRequest {
            id: "direct".into(),
            target: "host".into(),
            secrets: vec![IDENTIFIER.into()],
        })
        .unwrap();
    let error = loop {
        match SecretWriter::poll_approval(&mut controller) {
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Ok(Some(_)) => panic!("operator key was offered for deployment"),
            Err(error) => break error,
        }
    };
    assert!(error.contains("operator-only"), "{error}");
}

#[test]
fn pipe_secret_wrapper_delivers_exact_bytes_on_stdin() {
    let fixture = fixture();
    fixture.controller().generate_keypair(IDENTIFIER).unwrap();
    let received = fixture.temp.path().join("received");
    let output = fixture.pipe_secret(
        &[
            IDENTIFIER,
            "--",
            "sh",
            "-c",
            &format!("cat > '{}'; exit 7", received.display()),
        ],
        Stdio::piped(),
    );
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(output.stdout.is_empty());
    assert_eq!(
        std::fs::read(&received).unwrap(),
        b"NMBLSK01\0\x01private-bytes"
    );
}

#[test]
fn pipe_secret_producer_writes_only_the_value_and_refuses_a_terminal() {
    let fixture = fixture();
    fixture.controller().generate_keypair(IDENTIFIER).unwrap();
    let output = fixture.pipe_secret(&[IDENTIFIER], Stdio::piped());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"NMBLSK01\0\x01private-bytes");
    // With stdout on a real pseudo-terminal (util-linux `script`), it
    // refuses and prints nothing of the value.
    let command = [
        env!("CARGO_BIN_EXE_nix-secrets"),
        "pipe-secret",
        "--secret-identity",
        fixture.identity.to_str().unwrap(),
        "--backend-socket",
        fixture.socket.to_str().unwrap(),
        "--schema-file",
        fixture.schema_file.to_str().unwrap(),
        IDENTIFIER,
    ]
    .map(|argument| format!("'{argument}'"))
    .join(" ");
    let log = fixture.temp.path().join("terminal.log");
    let status = Command::new("script")
        .args(["-q", "-e", "-c", &command])
        .arg(&log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .expect("util-linux script is required for the terminal check");
    assert!(!status.success());
    let screen = std::fs::read(&log).unwrap();
    assert!(String::from_utf8_lossy(&screen).contains("refusing to write a secret to a terminal"));
    assert!(!screen.windows(13).any(|w| w == b"private-bytes"));
    // An unset value is an error, not empty output.
    let output = fixture.pipe_secret(&["host.services.signing.token"], Stdio::piped());
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unset"));
}

/// The real-world contract: NMBL's `nmbl-sign keygen --stdio`, stored,
/// then `pipe-secret … -- nmbl-sign sign --key-stdin` and a verification with
/// the public key read from the store. Needs network and Nix, so it runs only
/// with NIX_SECRETS_NMBL_SIGN=/path/to/nmbl-sign.
#[test]
fn nmbl_sign_keypair_signs_and_verifies_through_pipe_secret() {
    let Some(nmbl_sign) =
        std::env::var_os("NIX_SECRETS_NMBL_SIGN").filter(|value| !value.is_empty())
    else {
        eprintln!("skipped: set NIX_SECRETS_NMBL_SIGN to an nmbl-sign binary");
        return;
    };
    fn real(_: &nix_secrets_core::KeypairGenerator) -> Result<Keypair, String> {
        let program = std::env::var_os("NIX_SECRETS_NMBL_SIGN").unwrap();
        keypair::run(&[
            program,
            "keygen".into(),
            "--alg".into(),
            "ml-dsa-65".into(),
            "--stdio".into(),
        ])
    }
    let fixture = fixture();
    fixture
        .controller()
        .with_keypair_runner(real)
        .generate_keypair(IDENTIFIER)
        .unwrap();
    let document: toml::Value = toml::from_str(&fixture.store()).unwrap();
    use base64::Engine;
    let public = base64::engine::general_purpose::STANDARD
        .decode(
            document["secrets"][IDENTIFIER]["public_key"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(public.len(), 1952, "raw ML-DSA-65 public key");
    let dir = fixture.temp.path();
    std::fs::write(dir.join("key.pub"), &public).unwrap();
    std::fs::write(dir.join("image"), b"boot image").unwrap();
    let nmbl = nmbl_sign.to_str().unwrap();
    let image = dir.join("image");
    let output = fixture.pipe_secret(
        &[
            IDENTIFIER,
            "--",
            nmbl,
            "sign",
            "--key-stdin",
            "--domain",
            "generation-image",
            image.to_str().unwrap(),
        ],
        Stdio::piped(),
    );
    assert!(output.status.success(), "{output:?}");
    let verified = Command::new(nmbl)
        .args(["verify", "--key"])
        .arg(dir.join("key.pub"))
        .args(["--domain", "generation-image"])
        .arg(&image)
        .arg("--sig")
        .arg(dir.join("image.sig"))
        .status()
        .unwrap();
    assert!(verified.success());
    eprintln!("nmbl-sign signature verified with the stored public key");
}
