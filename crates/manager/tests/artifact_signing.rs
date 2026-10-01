//! Real backend + operator channel + encrypted key + trusted client signer.
//! This is a non-VM transport/crypto regression, not a fleet-install substitute.
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::{
    artifact_signing::{Artifact, Manifest, SigningRequest, REQUIRED_ROLES},
    framing::{read_json, write_json},
    Backend, Request, Response, Schema, SecretPath, SecretStore,
};
use nix_secrets_crypto::{AgeCommandProvider, CryptoError, CryptoProvider, Recipient};
use nix_secrets_manager::{
    client::BackendClient,
    keypair,
    operator_channel::{self, ChannelEvent, Decision},
};
use sha2::{Digest, Sha256, Sha512};
use std::{
    os::unix::net::UnixStream,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};
use zeroize::Zeroizing;
const IDENTIFIER: &str = "host.services.nmbl.generation-key";
struct Counted {
    age: AgeCommandProvider,
    count: Arc<AtomicUsize>,
}
impl CryptoProvider for Counted {
    fn encrypt(&self, recipients: &[&str], bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.age.encrypt(recipients, bytes)
    }
    fn decrypt(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.age.decrypt(bytes)
    }
    fn decrypt_batch(&self, bytes: &[&[u8]]) -> Result<Vec<Zeroizing<Vec<u8>>>, CryptoError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.age.decrypt_batch(bytes)
    }
}
#[test]
fn encrypted_key_is_decrypted_once_on_client_and_backend_returns_only_verified_sidecars() {
    let Ok(signer) = std::env::var("NIX_SECRETS_ARTIFACT_SIGNER") else {
        eprintln!("artifact signer integration requires NIX_SECRETS_ARTIFACT_SIGNER; not run");
        return;
    };
    let artifact = std::env::var("NIX_SECRETS_SIGNING_TEST_ARTIFACT").unwrap_or_else(|_| {
        std::fs::canonicalize("/run/current-system/sw/bin/true")
            .unwrap()
            .to_string_lossy()
            .into()
    });
    let bytes = std::fs::read(&artifact).unwrap();
    let manifest = Manifest {
        artifacts: REQUIRED_ROLES
            .iter()
            .map(|role| Artifact {
                role: role.to_string(),
                path: artifact.clone(),
                sha512: format!("{:x}", Sha512::digest(&bytes)),
                size: bytes.len() as u64,
            })
            .collect(),
    };
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("id");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&identity)
        .status()
        .unwrap()
        .success());
    let recipient = std::fs::read_to_string(identity.with_extension("pub")).unwrap();
    let socket = temp.path().join("backend.sock");
    let schema = Schema::from_json(&serde_json::json!({"host":{"metadata":{"socketPath":socket,"deployment":{"host":"host","destination":"forward@host","port":22}},"services":{"nmbl":{"generation-key":{"kind":"operator","signingOnly":true,"generator":{"installable":"trusted-test#nmbl-sign","args":["keygen"]},"recipientPublicKeys":[recipient.trim()],"recipientIds":["operator"]}}}}}).to_string()).unwrap();
    let backend = Backend::bind(
        &socket,
        schema.clone(),
        SecretStore::new(temp.path().join("nix-secrets.toml")),
    )
    .unwrap();
    std::thread::spawn(move || backend.serve().unwrap());
    let pair = keypair::run(&[
        signer.clone().into(),
        "keygen".into(),
        "--alg".into(),
        "ml-dsa-65".into(),
        "--stdio".into(),
    ])
    .unwrap();
    let fingerprint = format!("{:x}", Sha256::digest(&pair.public));
    let count = Arc::new(AtomicUsize::new(0));
    let provider = Counted {
        age: AgeCommandProvider::identity_file(identity),
        count: count.clone(),
    };
    let mut client = BackendClient::new(UnixStream::connect(&socket).unwrap());
    client
        .set_private_key(
            &SecretPath::parse(IDENTIFIER).unwrap(),
            &pair.private,
            &[Recipient {
                id: "operator",
                ssh_public_key: recipient.trim(),
            }],
            &provider,
            STANDARD.encode(&pair.public),
        )
        .unwrap();
    let (events, receiver) = mpsc::channel();
    let (decisions, decision_receiver) = mpsc::channel();
    let operator_socket = socket.clone();
    let controller_schema = schema.clone();
    std::thread::spawn(move || {
        let _ = operator_channel::run(
            &operator_socket,
            &schema,
            &provider,
            "test age identity",
            &events,
            &decision_receiver,
        );
    });
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
        ChannelEvent::Attached
    ));
    let requester_socket = socket.clone();
    let request_manifest = manifest.clone();
    let requester = std::thread::spawn(move || {
        use std::io::Write;
        let mut child = Command::new(env!("CARGO_BIN_EXE_nix-secrets"))
            .args(["sign-artifacts", "--backend-socket"])
            .arg(requester_socket)
            .args([
                "--host",
                "host",
                "--reason",
                "Sign this host's initial verified boot generation",
                IDENTIFIER,
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&request_manifest).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Response::ArtifactSignatures {
            signatures: serde_json::from_slice(&output.stdout).unwrap(),
        }
    });
    let prompt = match receiver.recv_timeout(Duration::from_secs(10)).unwrap() {
        ChannelEvent::Prompt(prompt) => prompt,
        _ => panic!("expected signing approval"),
    };
    assert!(prompt.artifact_signature);
    assert!(!prompt.ssh_signature);
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(prompt.values[0]
        .description
        .as_ref()
        .unwrap()
        .contains(&fingerprint));
    decisions
        .send(Decision {
            id: "stale-request-id".into(),
            approved: true,
        })
        .unwrap();
    decisions
        .send(Decision {
            id: prompt.id.clone(),
            approved: true,
        })
        .unwrap();
    let signatures = match requester.join().unwrap() {
        Response::ArtifactSignatures { signatures } => signatures,
        other => panic!("unexpected response: {other:?}"),
    };
    signatures.validate(&manifest).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    for signature in signatures.signatures {
        let sidecar = temp.path().join(format!("{}.sig", signature.role));
        std::fs::write(
            &sidecar,
            STANDARD.decode(signature.signature_base64).unwrap(),
        )
        .unwrap();
        let public = temp.path().join("public");
        std::fs::write(&public, &pair.public).unwrap();
        assert!(Command::new(&signer)
            .args(["verify", "--key"])
            .arg(&public)
            .args(["--domain", &signature.role, "--sig"])
            .arg(&sidecar)
            .arg(&artifact)
            .status()
            .unwrap()
            .success());
    }
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
        ChannelEvent::ArtifactSignatureFinished { result: Ok(()), .. }
    ));
    // Tampering is refused before a prompt or a provider authorization.
    for wrong_key in [false, true] {
        let mut changed = manifest.clone();
        if !wrong_key {
            changed.artifacts[0].sha512 = "0".repeat(128);
        }
        let request = SigningRequest {
            identifier: IDENTIFIER.into(),
            host: "host".into(),
            public_key_sha256: if wrong_key {
                "0".repeat(64)
            } else {
                fingerprint.clone()
            },
            manifest: changed,
        };
        let mut stream = UnixStream::connect(&socket).unwrap();
        write_json(
            &mut stream,
            &Request::RequestArtifactSignatures {
                request,
                reason: None,
            },
        )
        .unwrap();
        assert!(matches!(
            read_json::<Response>(&mut stream).unwrap().unwrap(),
            Response::Error { .. }
        ));
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
            ChannelEvent::ArtifactSignatureFinished { result: Err(_), .. }
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
    // Explicit rejection never decrypts the key.
    let request = SigningRequest {
        identifier: IDENTIFIER.into(),
        host: "host".into(),
        public_key_sha256: fingerprint.clone(),
        manifest: manifest.clone(),
    };
    let denied_socket = socket.clone();
    let denied_request = request.clone();
    let denied = std::thread::spawn(move || {
        let mut stream = UnixStream::connect(denied_socket).unwrap();
        write_json(
            &mut stream,
            &Request::RequestArtifactSignatures {
                request: denied_request,
                reason: None,
            },
        )
        .unwrap();
        read_json::<Response>(&mut stream).unwrap().unwrap()
    });
    let prompt = match receiver.recv_timeout(Duration::from_secs(10)).unwrap() {
        ChannelEvent::Prompt(prompt) => prompt,
        _ => panic!("expected approval"),
    };
    decisions
        .send(Decision {
            id: prompt.id,
            approved: false,
        })
        .unwrap();
    assert!(
        matches!(denied.join().unwrap(), Response::Error { message } if message.contains("denied"))
    );
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
        ChannelEvent::ArtifactSignatureFinished { result: Err(_), .. }
    ));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    // A requester disconnect releases its artifact registry. A late approval
    // must fail before decryption, even while the original prompt is visible.
    let mut gone = UnixStream::connect(&socket).unwrap();
    write_json(
        &mut gone,
        &Request::RequestArtifactSignatures {
            request,
            reason: None,
        },
    )
    .unwrap();
    let prompt = match receiver.recv_timeout(Duration::from_secs(10)).unwrap() {
        ChannelEvent::Prompt(prompt) => prompt,
        _ => panic!("expected approval"),
    };
    drop(gone);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while client
        .read_signing_artifact(&prompt.id, "generation-image", 0)
        .is_ok()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "disconnected request remained registered"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    decisions
        .send(Decision {
            id: prompt.id,
            approved: true,
        })
        .unwrap();
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
        ChannelEvent::ArtifactSignatureFinished { result: Err(_), .. }
    ));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    // Signing-only exports fail before any operator/provider action.
    let mut stream = UnixStream::connect(&socket).unwrap();
    write_json(
        &mut stream,
        &Request::RequestSecrets {
            identifiers: vec![IDENTIFIER.into()],
            reason: None,
        },
    )
    .unwrap();
    assert!(
        matches!(read_json::<Response>(&mut stream).unwrap().unwrap(), Response::Error { message } if message.contains("plaintext export is forbidden"))
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let mut export_client = BackendClient::new(UnixStream::connect(&socket).unwrap());
    assert!(nix_secrets_manager::secret_values::load(
        &mut export_client,
        &controller_schema,
        &[IDENTIFIER.into()]
    )
    .err()
    .unwrap()
    .contains("plaintext export is forbidden"));
    let mut controller = nix_secrets_manager::controller::Controller::new(
        export_client,
        controller_schema,
        AgeCommandProvider::default(),
        vec![],
    )
    .unwrap();
    assert!(controller
        .reveal_secret(IDENTIFIER)
        .err()
        .unwrap()
        .contains("plaintext export is forbidden"));
    use nix_secrets_manager::ui::SecretWriter;
    assert!(controller
        .reveal(IDENTIFIER)
        .err()
        .unwrap()
        .contains("plaintext export is forbidden"));
}
