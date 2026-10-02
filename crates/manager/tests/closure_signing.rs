//! Native Ed25519 signing through the real broker, CLI and approving operator.
//! The reversible test provider exercises secret framing without an external age process.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, SigningKey, Verifier};
use nix_secrets_core::{
    closure_signing::{Manifest, ManifestPath, Signatures, SigningRequest},
    framing::{read_json, write_json},
    Backend, Request, Response, Schema, SecretPath, SecretStore,
};
use nix_secrets_crypto::{CryptoError, CryptoProvider, Recipient};
use nix_secrets_manager::{
    client::BackendClient,
    operator_channel::{self, ChannelEvent, Decision, SecretPrompt},
};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

const IDENTIFIER: &str = "host.services.nix.closure-key";
#[derive(Clone)]
struct Counted {
    count: Arc<AtomicUsize>,
}
impl CryptoProvider for Counted {
    fn encrypt(&self, _: &[&str], bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(bytes.iter().map(|b| b ^ 0xa5).collect())
    }
    fn decrypt(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(bytes.iter().map(|b| b ^ 0xa5).collect()))
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    socket: PathBuf,
    client: BackendClient,
    schema: Schema,
    count: Arc<AtomicUsize>,
    events: Receiver<ChannelEvent>,
    decisions: Sender<Decision>,
    key: SigningKey,
    fingerprint: String,
    manifest: Manifest,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("nix-secrets");
        std::fs::create_dir(&runtime).unwrap();
        let socket = runtime.join(nix_secrets_manager::startup::socket_name(directory.path()));
        let schema=Schema::from_json(&serde_json::json!({"host":{"metadata":{"socketPath":socket,"deployment":{"host":"host","destination":"forward@host","port":22}},"services":{"nix":{"closure-key":{"kind":"operator","signingOnly":true,"generator":{"installable":"test#nix-key","args":[]},"recipientPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f test"],"recipientIds":["operator"]}}}}}).to_string()).unwrap();
        let backend = Backend::bind(
            &socket,
            schema.clone(),
            SecretStore::new(directory.path().join("secrets.toml")),
        )
        .unwrap();
        thread::spawn(move || backend.serve().unwrap());
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let private = Zeroizing::new(
            format!("cache:{}\n", STANDARD.encode(key.to_keypair_bytes())).into_bytes(),
        );
        let public = format!(
            "cache:{}\n",
            STANDARD.encode(key.verifying_key().to_bytes())
        );
        let fingerprint = format!("{:x}", Sha256::digest(public.as_bytes()));
        let count = Arc::new(AtomicUsize::new(0));
        let provider = Counted {
            count: count.clone(),
        };
        let mut client = BackendClient::new(UnixStream::connect(&socket).unwrap());
        client
            .set_private_key(
                &SecretPath::parse(IDENTIFIER).unwrap(),
                &private,
                &[Recipient {
                    id: "operator",
                    ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f test",
                }],
                &provider,
                STANDARD.encode(public),
            )
            .unwrap();
        let (events, receiver) = mpsc::channel();
        let (decisions, decision_receiver) = mpsc::channel();
        let operator_socket = socket.clone();
        let operator_schema = schema.clone();
        thread::spawn(move || {
            let _ = operator_channel::run(
                &operator_socket,
                &operator_schema,
                &provider,
                "counted test identity",
                &events,
                &decision_receiver,
            );
        });
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
            ChannelEvent::Attached
        ));
        let path = |name: &str| format!("/nix/store/{}-{name}", "0".repeat(32));
        let manifest = Manifest {
            version: 1,
            paths: vec![
                ManifestPath {
                    path: path("a"),
                    nar_hash: format!("sha256:{}", "0".repeat(52)),
                    nar_size: 7,
                    references: vec![path("b")],
                },
                ManifestPath {
                    path: path("b"),
                    nar_hash: format!("sha256:1{}", "0".repeat(51)),
                    nar_size: 11,
                    references: vec![],
                },
            ],
        };
        Self {
            _directory: directory,
            socket,
            client,
            schema,
            count,
            events: receiver,
            decisions,
            key,
            fingerprint,
            manifest,
        }
    }
    fn request(&self) -> SigningRequest {
        SigningRequest {
            identifier: IDENTIFIER.into(),
            host: "host".into(),
            public_key_sha256: self.fingerprint.clone(),
            manifest: self.manifest.clone(),
        }
    }
    fn start(&self, request: SigningRequest) -> thread::JoinHandle<Response> {
        let socket = self.socket.clone();
        thread::spawn(move || {
            let mut stream = UnixStream::connect(socket).unwrap();
            write_json(
                &mut stream,
                &Request::RequestClosureSignatures {
                    request,
                    reason: Some("test closure update".into()),
                },
            )
            .unwrap();
            read_json(&mut stream).unwrap().unwrap()
        })
    }
    fn prompt(&self) -> SecretPrompt {
        match self.events.recv_timeout(Duration::from_secs(5)).unwrap() {
            ChannelEvent::Prompt(p) => p,
            _ => panic!("expected closure prompt"),
        }
    }
    fn decide(&self, id: String, approved: bool) {
        self.decisions.send(Decision { id, approved }).unwrap();
    }
    fn finished(&self, success: bool) {
        match self.events.recv_timeout(Duration::from_secs(5)).unwrap() {
            ChannelEvent::ArtifactSignatureFinished { result, .. } => {
                assert_eq!(result.is_ok(), success)
            }
            _ => panic!("expected signature result"),
        }
    }
}

fn exchange(socket: &std::path::Path, request: &Request) -> std::io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;
    write_json(&mut stream, request)?;
    read_json(&mut stream)?.ok_or_else(|| std::io::Error::other("backend disconnected"))
}

#[test]
fn cli_default_repository_discovers_backend_and_returns_only_native_verified_signatures() {
    let mut f = Fixture::new();
    let repository = f._directory.path().to_path_buf();
    let manifest = f.manifest.clone();
    let cli = thread::spawn(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nix-secrets"))
            .arg("sign-closure")
            .current_dir(&repository)
            .env("XDG_RUNTIME_DIR", &repository)
            .args([
                "--host",
                "host",
                "--reason",
                "Sign the approved closure update",
                IDENTIFIER,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    });
    let prompt = f.prompt();
    assert!(prompt.closure_signature);
    assert!(!prompt.artifact_signature);
    assert!(!prompt.ssh_signature);
    assert_eq!(prompt.values.len(), 1);
    let description = prompt.values[0].description.as_ref().unwrap();
    assert!(description.contains(&f.fingerprint));
    assert!(description.contains("metadata"));
    assert!(description.contains("2 paths"));
    assert_eq!(f.count.load(Ordering::SeqCst), 0);
    f.decide("stale-request-id".into(), true);
    assert!(f.events.recv_timeout(Duration::from_millis(100)).is_err());
    assert_eq!(f.count.load(Ordering::SeqCst), 0);
    f.decide(prompt.id.clone(), true);
    let output = cli.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signatures: Signatures = serde_json::from_slice(&output.stdout).unwrap();
    signatures.validate(&f.manifest).unwrap();
    assert_eq!(f.count.load(Ordering::SeqCst), 1);
    for signature in &signatures.signatures {
        let path = f
            .manifest
            .paths
            .iter()
            .find(|p| p.path == signature.path)
            .unwrap();
        let (name, bytes) = signature.signature.split_once(':').unwrap();
        assert_eq!(name, "cache");
        let bytes: [u8; 64] = STANDARD.decode(bytes).unwrap().try_into().unwrap();
        f.key
            .verifying_key()
            .verify(
                path.fingerprint().as_bytes(),
                &Signature::from_bytes(&bytes),
            )
            .unwrap();
        assert!(f
            .key
            .verifying_key()
            .verify(b"altered closure metadata", &Signature::from_bytes(&bytes))
            .is_err());
    }
    f.finished(true);
    assert!(matches!(
        exchange(
            &f.socket,
            &Request::CheckClosureSigningRequest {
                request_id: prompt.id
            }
        )
        .unwrap(),
        Response::Error { .. }
    ));
    // Plaintext exports are refused before an operator prompt or decryption.
    assert!(
        matches!(exchange(&f.socket, &Request::RequestSecrets {identifiers:vec![IDENTIFIER.into()],reason:None}).unwrap(),Response::Error {message} if message.contains("plaintext export is forbidden"))
    );
    assert!(nix_secrets_manager::secret_values::load(
        &mut f.client,
        &f.schema,
        &[IDENTIFIER.into()]
    )
    .err()
    .unwrap()
    .contains("plaintext export is forbidden"));
    assert_eq!(f.count.load(Ordering::SeqCst), 1);
    assert!(f.events.recv_timeout(Duration::from_millis(100)).is_err());
}

#[test]
fn denial_invalid_metadata_stale_public_key_and_disconnect_never_decrypt() {
    let f = Fixture::new();
    for request in [
        {
            let mut r = f.request();
            r.public_key_sha256 = "0".repeat(64);
            r
        },
        {
            let mut r = f.request();
            r.manifest.paths[0]
                .references
                .push("/nix/store/../../private".into());
            r
        },
    ] {
        assert!(matches!(
            f.start(request).join().unwrap(),
            Response::Error { .. }
        ));
        assert!(f.events.recv_timeout(Duration::from_millis(100)).is_err());
        assert_eq!(f.count.load(Ordering::SeqCst), 0);
    }
    let requester = f.start(f.request());
    let prompt = f.prompt();
    f.decide(prompt.id.clone(), false);
    assert!(
        matches!(requester.join().unwrap(),Response::Error {message} if message.contains("denied"))
    );
    f.finished(false);
    assert_eq!(f.count.load(Ordering::SeqCst), 0);
    let mut gone = UnixStream::connect(&f.socket).unwrap();
    write_json(
        &mut gone,
        &Request::RequestClosureSignatures {
            request: f.request(),
            reason: None,
        },
    )
    .unwrap();
    let prompt = f.prompt();
    drop(gone);
    // The check inspects socket liveness directly, independent of polling delay.
    assert!(matches!(
        exchange(
            &f.socket,
            &Request::CheckClosureSigningRequest {
                request_id: prompt.id.clone()
            }
        )
        .unwrap(),
        Response::Error { .. }
    ));
    f.decide(prompt.id.clone(), true);
    f.finished(false);
    assert_eq!(f.count.load(Ordering::SeqCst), 0);
    assert!(matches!(
        exchange(
            &f.socket,
            &Request::CheckClosureSigningRequest {
                request_id: prompt.id
            }
        )
        .unwrap(),
        Response::Error { .. }
    ));
}

#[test]
fn closed_decision_channel_never_decrypts() {
    let f = Fixture::new();
    let requester = f.start(f.request());
    let prompt = f.prompt();
    drop(f.decisions);
    match f.events.recv_timeout(Duration::from_secs(5)).unwrap() {
        ChannelEvent::ArtifactSignatureFinished {
            result: Err(message),
            ..
        } => assert!(message.contains("in time")),
        _ => panic!("expected closed decision channel rejection"),
    }
    assert!(
        matches!(requester.join().unwrap(),Response::Error {message} if message.contains("in time"))
    );
    assert_eq!(f.count.load(Ordering::SeqCst), 0);
    assert!(matches!(
        exchange(
            &f.socket,
            &Request::CheckClosureSigningRequest {
                request_id: prompt.id
            }
        )
        .unwrap(),
        Response::Error { .. }
    ));
}

#[test]
fn cli_explicit_repository_overrides_unrelated_working_directory() {
    let mut f = Fixture::new();
    let repository = f._directory.path().to_path_buf();
    let unrelated = tempfile::tempdir().unwrap();
    let cwd = unrelated.path().to_path_buf();
    let manifest = f.manifest.clone();
    let cli = thread::spawn(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nix-secrets"))
            .args(["sign-closure", "--repository"])
            .arg(&repository)
            .args([
                "--host",
                "host",
                "--reason",
                "Sign explicit repository closure",
                IDENTIFIER,
            ])
            .current_dir(cwd)
            .env("XDG_RUNTIME_DIR", &repository)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    });
    let prompt = f.prompt();
    assert!(prompt.closure_signature);
    f.decide(prompt.id, true);
    let output = cli.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signatures: Signatures = serde_json::from_slice(&output.stdout).unwrap();
    signatures.validate(&f.manifest).unwrap();
    assert_eq!(f.count.load(Ordering::SeqCst), 1);
}
