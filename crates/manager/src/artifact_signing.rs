//! Detached artifact signing on the operator's client. The backend sees public
//! artifact bytes and signatures, and never receives the decrypted signing key.
use crate::{
    client::BackendClient,
    operator_channel::{ChannelEvent, Decision, SecretPrompt, DECISION_TIMEOUT},
    secret_values,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::{
    artifact_signing::{Manifest, Signatures, SigningRequest, MAX_MANIFEST_BYTES},
    secret_request::{SecretAnswer, SecretRequest},
    LeafSpec, Request, Response, Schema, SecretPath,
};
use nix_secrets_crypto::CryptoProvider;
use sha2::{Digest, Sha256, Sha512};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};
use zeroize::Zeroizing;

fn fingerprint(public: &str) -> Result<String, String> {
    let bytes = STANDARD
        .decode(public)
        .map_err(|_| "stored signing public key is not base64")?;
    if ![1952, 2592].contains(&bytes.len()) {
        return Err("invalid ML-DSA public key length".into());
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// The executable is selected exclusively by the frontend's local environment.
/// Neither backend schema nor requester may choose a command or arguments.
fn trusted_signer() -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    let path = std::env::var_os("NIX_SECRETS_ARTIFACT_SIGNER").ok_or(
        "this client has no trusted artifact signer configured (NIX_SECRETS_ARTIFACT_SIGNER)",
    )?;
    let path = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
    let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    let store = std::fs::metadata("/nix/store").map_err(|e| e.to_string())?;
    if !path.starts_with("/nix/store")
        || !metadata.is_file()
        || metadata.mode() & 0o222 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.uid() != store.uid()
    {
        return Err(
            "trusted artifact signer must be an immutable executable in the client's Nix store"
                .into(),
        );
    }
    Ok(path)
}

pub(crate) fn handle(
    request: &SecretRequest,
    signing: &SigningRequest,
    client: &mut BackendClient,
    schema: &Schema,
    provider: &impl CryptoProvider,
    identity: &str,
    events: &Sender<ChannelEvent>,
    decisions: &Receiver<Decision>,
) -> (SecretAnswer, ChannelEvent) {
    let label = format!(
        "artifact update of {} (PID {})",
        signing.host, request.requester.pid
    );
    let deny = |reason: String| {
        (
            SecretAnswer::Denied {
                reason: reason.clone(),
            },
            ChannelEvent::ArtifactSignatureFinished {
                requester: label.clone(),
                result: Err(reason),
            },
        )
    };
    let prepare = (|| {
        signing.validate()?;
        if request.ssh_signature.is_some() || request.identifiers != [signing.identifier.clone()] {
            return Err("artifact signing request mixed with other operations".into());
        }
        let path = SecretPath::parse(&signing.identifier).map_err(|e| e.to_string())?;
        match schema.leaf(&path).map_err(|e| e.to_string())? {
            LeafSpec::Operator(spec) if spec.signing_only => {}
            _ => return Err("artifact signing requires a signing-only operator key".into()),
        }
        let signer = trusted_signer()?;
        let record = client
            .get(&path)
            .map_err(|e| e.to_string())?
            .ok_or("signing key is unset")?;
        if fingerprint(
            record
                .public_key
                .as_deref()
                .ok_or("signing key has no public half")?,
        )? != signing.public_key_sha256
        {
            return Err("signing public-key fingerprint differs from stored key".into());
        }
        let batch = secret_values::load_for_signing(client, schema, &[signing.identifier.clone()])?;
        // Hash streamed bytes before displaying approval. No requester digest is
        // trusted, and the entire multi-gigabyte image is never held in memory.
        for artifact in &signing.manifest.artifacts {
            let mut hash = Sha512::new();
            let mut offset = 0;
            while offset < artifact.size {
                let bytes = client.read_signing_artifact(&request.id, &artifact.role, offset)?;
                if bytes.len() as u64 > artifact.size - offset {
                    return Err("artifact chunk exceeds approved size".into());
                }
                offset += bytes.len() as u64;
                hash.update(bytes);
            }
            if format!("{:x}", hash.finalize()) != artifact.sha512 {
                return Err(format!(
                    "{} artifact digest differs from streamed bytes",
                    artifact.role
                ));
            }
        }
        Ok((signer, batch))
    })();
    let (signer, batch) = match prepare {
        Ok(result) => result,
        Err(error) => return deny(error),
    };
    let mut values = batch.values.clone();
    values[0].description = Some(format!(
        "Host: {}\nPublic key SHA256: {}\n{}",
        signing.host,
        signing.public_key_sha256,
        signing
            .manifest
            .artifacts
            .iter()
            .map(|a| format!("Verified {}: {} bytes\nSHA512 {}", a.role, a.size, a.sha512))
            .collect::<Vec<_>>()
            .join("\n")
    ));
    let prompt = SecretPrompt {
        id: request.id.clone(),
        values,
        identity: identity.into(),
        requester: request.requester.clone(),
        parent: request.parent.clone(),
        reason: request.reason.clone(),
        ssh_signature: false,
        artifact_signature: true,
        deadline: Instant::now() + DECISION_TIMEOUT,
    };
    let deadline = prompt.deadline;
    while decisions.try_recv().is_ok() {}
    if events.send(ChannelEvent::Prompt(prompt)).is_err() {
        return deny("the TUI closed".into());
    }
    loop {
        match decisions.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(decision) if decision.id == request.id => {
                if !decision.approved {
                    return deny("operator denied artifact signing".into());
                }
                break;
            }
            Ok(_) => {}
            Err(_) => return deny("operator did not approve artifact signing in time".into()),
        }
    }
    // Recheck the live opaque request after approval, before asking a provider
    // to decrypt. A disconnected requester has lost its file registry.
    if let Err(error) =
        client.read_signing_artifact(&request.id, &signing.manifest.artifacts[0].role, 0)
    {
        return deny(error);
    }
    let result = batch.decrypt(provider).and_then(|mut values| {
        let key = values
            .remove(&signing.identifier)
            .ok_or("signing key missing after decryption")?;
        sign_locally(&signer, signing, &key)
    });
    match result {
        Ok(signatures) => (
            SecretAnswer::ArtifactsSigned { signatures },
            ChannelEvent::ArtifactSignatureFinished {
                requester: label,
                result: Ok(()),
            },
        ),
        Err(error) => deny(error),
    }
}

fn sign_locally(
    signer: &std::path::Path,
    request: &SigningRequest,
    key: &[u8],
) -> Result<Signatures, String> {
    // Only bounded key containers can enter the trusted local signer.
    if key.len() > 16384 {
        return Err("signing key container is oversized".into());
    }
    let encoded = Zeroizing::new(STANDARD.encode(key));
    // Serialize into a fixed-capacity zeroized buffer; serde's borrowed key
    // string is never copied into an unprotected JSON Value.
    #[derive(serde::Serialize)]
    struct Input<'a> {
        public_key_sha256: &'a str,
        key_base64: &'a str,
        artifacts: Vec<ArtifactDigest<'a>>,
    }
    #[derive(serde::Serialize)]
    struct ArtifactDigest<'a> {
        role: &'a str,
        sha512: &'a str,
        size: u64,
    }
    let input = Input {
        public_key_sha256: &request.public_key_sha256,
        key_base64: &encoded,
        artifacts: request
            .manifest
            .artifacts
            .iter()
            .map(|a| ArtifactDigest {
                role: &a.role,
                sha512: &a.sha512,
                size: a.size,
            })
            .collect(),
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_MANIFEST_BYTES));
    serde_json::to_writer(&mut *bytes, &input).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err("local signing request exceeds bound".into());
    }
    let mut child = Command::new(signer)
        .arg("sign-digests")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdin = child.stdin.take().ok_or("signer stdin missing")?;
    let mut stdout = child.stdout.take().ok_or("signer stdout missing")?;
    let (sent, output) = std::thread::scope(|scope| {
        let sent = scope.spawn(move || stdin.write_all(&bytes));
        let mut output = Vec::new();
        let read = (&mut stdout)
            .take((MAX_MANIFEST_BYTES + 1) as u64)
            .read_to_end(&mut output);
        if output.len() > MAX_MANIFEST_BYTES || read.is_err() {
            let _ = child.kill();
        }
        (
            sent.join()
                .map_err(|_| "local signer input thread failed".to_owned())
                .and_then(|r| r.map_err(|e| e.to_string())),
            read.map(|_| output).map_err(|e| e.to_string()),
        )
    });
    let status = child.wait().map_err(|e| e.to_string())?;
    sent?;
    let output = output?;
    if !status.success() || output.len() > MAX_MANIFEST_BYTES {
        return Err("trusted client signer failed".into());
    }
    let signatures: Signatures = serde_json::from_slice(&output)
        .map_err(|e| format!("invalid client signer response: {e}"))?;
    signatures.validate(&request.manifest)?;
    Ok(signatures)
}

/// CLI consumed by a generic external signing command. No local/decryption
/// mode exists: only the attached production frontend may sign.
pub fn run(arguments: Vec<std::ffi::OsString>, runtime: &std::path::Path) -> Result<(), String> {
    let mut options = crate::with_secrets::Options {
        repository: std::env::current_dir().map_err(|e| e.to_string())?,
        ..Default::default()
    };
    let mut identifier = None;
    let mut host = None;
    let mut args = arguments.into_iter();
    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or("sign-artifacts arguments must be UTF8")?;
        if text == "--host" {
            host = Some(
                args.next()
                    .ok_or("--host requires name")?
                    .into_string()
                    .map_err(|_| "host must be UTF8")?,
            );
        } else if crate::with_secrets::parse_option(text, &mut args, &mut options)? {
        } else if text.starts_with('-') || identifier.is_some() {
            return Err("usage: nix-secrets sign-artifacts [--repository PATH] [--backend-socket PATH] --host HOST --reason TEXT IDENTIFIER".into());
        } else {
            identifier = Some(text.to_owned());
        }
    }
    if options.local
        || options.identity.is_some()
        || options.shared_session
        || options.schema_file.is_some()
    {
        return Err("artifact signing only runs in the attached TUI".into());
    }
    crate::with_secrets::check_options(&options)?;
    let identifier = identifier.ok_or("sign-artifacts requires signing identifier")?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err("artifact manifest exceeds 64KiB".into());
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut stream =
        crate::with_secrets::connect_backend(&options, runtime).map_err(|e| e.to_string())?;
    let mut client = BackendClient::new(stream.try_clone().map_err(|e| e.to_string())?);
    let path = SecretPath::parse(&identifier).map_err(|e| e.to_string())?;
    let record = client
        .get(&path)
        .map_err(|e| e.to_string())?
        .ok_or("signing key is unset")?;
    let request = SigningRequest {
        identifier,
        host: host.ok_or("--host is required")?,
        public_key_sha256: fingerprint(
            record
                .public_key
                .as_deref()
                .ok_or("signing key has no public half")?,
        )?,
        manifest,
    };
    request.validate()?;
    nix_secrets_core::framing::write_json(
        &mut stream,
        &Request::RequestArtifactSignatures {
            request,
            reason: options.reason,
        },
    )
    .map_err(|e| e.to_string())?;
    match nix_secrets_core::framing::read_json::<Response>(&mut stream)
        .map_err(|e| e.to_string())?
    {
        Some(Response::ArtifactSignatures { signatures }) => {
            serde_json::to_writer(std::io::stdout(), &signatures).map_err(|e| e.to_string())
        }
        Some(Response::Error { message }) => Err(message),
        _ => Err("backend did not return detached signatures".into()),
    }
}
