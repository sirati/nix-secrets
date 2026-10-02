//! Standard Nix closure signatures made only in the approving client.
use crate::{
    client::BackendClient,
    operator_channel::{ChannelEvent, Decision, SecretPrompt, DECISION_TIMEOUT},
    secret_values,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use nix_secrets_core::{
    closure_signing::{Manifest, PathSignature, Signatures, SigningRequest, MAX_MANIFEST_BYTES},
    secret_request::{SecretAnswer, SecretRequest},
    LeafSpec, Request, Response, Schema, SecretPath,
};
use nix_secrets_crypto::CryptoProvider;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    io::Read,
    path::Path,
    sync::mpsc::{Receiver, Sender},
    time::Instant,
};
use zeroize::Zeroizing;

fn public_envelope(encoded: &str) -> Result<(String, [u8; 32], String), String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "invalid Nix public-key envelope")?;
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let (name, key) = parse_named(&bytes)?;
    let public: [u8; 32] = STANDARD
        .decode(key)
        .map_err(|_| "invalid Nix public key")?
        .try_into()
        .map_err(|_| "Nix public key must be 32 bytes")?;
    Ok((name.to_owned(), public, hash))
}
fn parse_named(bytes: &[u8]) -> Result<(&str, &str), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Nix signing key must be text")?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let (name, key) = text
        .split_once(':')
        .ok_or("Nix signing key requires name:base64")?;
    if name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || key.is_empty()
        || key.bytes().any(|b| b.is_ascii_whitespace())
    {
        return Err("invalid named Nix signing key".into());
    }
    Ok((name, key))
}
fn sign(
    manifest: &Manifest,
    key: &[u8],
    expected_name: &str,
    expected_public: &[u8; 32],
) -> Result<Signatures, String> {
    manifest.validate()?;
    if key.len() > 512 {
        return Err("Nix secret key is oversized".into());
    }
    let (name, encoded) = parse_named(key)?;
    if name != expected_name {
        return Err("Nix secret key name differs from public record".into());
    }
    let bytes = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| "invalid Nix secret key")?,
    );
    let raw = Zeroizing::new(
        <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| "Nix secret key must be 64 bytes")?,
    );
    let key =
        SigningKey::from_keypair_bytes(&raw).map_err(|_| "Nix secret key pair is inconsistent")?;
    if key.verifying_key().to_bytes() != *expected_public {
        return Err("Nix secret key differs from public record".into());
    }
    let signatures = Signatures {
        version: 1,
        signatures: manifest
            .paths
            .iter()
            .map(|path| PathSignature {
                path: path.path.clone(),
                signature: format!(
                    "{name}:{}",
                    STANDARD.encode(key.sign(path.fingerprint().as_bytes()).to_bytes())
                ),
            })
            .collect(),
    };
    signatures.validate(manifest)?;
    Ok(signatures)
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
        "Nix closure update of {} (PID {})",
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
    let prepared = (|| {
        signing.validate()?;
        if request.ssh_signature.is_some()
            || request.artifact_signature.is_some()
            || request.identifiers != [signing.identifier.clone()]
        {
            return Err("closure signing request mixes operations".into());
        }
        let path = SecretPath::parse(&signing.identifier).map_err(|e| e.to_string())?;
        match schema.leaf(&path).map_err(|e| e.to_string())? {
            LeafSpec::Operator(spec) if spec.signing_only => {}
            _ => return Err("closure signing requires a signing-only operator key".into()),
        }
        let record = client
            .get(&path)
            .map_err(|e| e.to_string())?
            .ok_or("Nix signing key is unset")?;
        let (name, public, hash) = public_envelope(
            record
                .public_key
                .as_deref()
                .ok_or("Nix signing key has no public half")?,
        )?;
        if hash != signing.public_key_sha256 {
            return Err("Nix public-key fingerprint differs from stored key".into());
        }
        let batch = secret_values::load_for_signing(client, schema, &[signing.identifier.clone()])?;
        Ok((name, public, batch))
    })();
    let (name, public, batch) = match prepared {
        Ok(v) => v,
        Err(e) => return deny(e),
    };
    let mut values = batch.values.clone();
    let metadata = serde_json::to_vec(&signing.manifest).expect("public metadata serializes");
    values[0].description=Some(format!("Host: {}\nNix public key name: {}\nPublic envelope SHA256: {}\nRequester-supplied metadata (NAR contents not verified): {} paths\nCanonical metadata SHA256: {:x}\nFirst {} of {} canonical fingerprints:\n{}",signing.host,name,signing.public_key_sha256,signing.manifest.paths.len(),Sha256::digest(metadata),signing.manifest.paths.len().min(8),signing.manifest.paths.len(),signing.manifest.paths.iter().take(8).map(|p|p.fingerprint()).collect::<Vec<_>>().join("\n")));
    let prompt = SecretPrompt {
        id: request.id.clone(),
        values,
        identity: identity.into(),
        requester: request.requester.clone(),
        parent: request.parent.clone(),
        reason: request.reason.clone(),
        ssh_signature: false,
        artifact_signature: false,
        closure_signature: true,
        deadline: Instant::now() + DECISION_TIMEOUT,
    };
    let deadline = prompt.deadline;
    while decisions.try_recv().is_ok() {}
    if events.send(ChannelEvent::Prompt(prompt)).is_err() {
        return deny("the TUI closed".into());
    }
    loop {
        match decisions.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(d) if d.id == request.id => {
                if !d.approved {
                    return deny("operator denied closure signing".into());
                }
                break;
            }
            Ok(_) => {}
            Err(_) => return deny("operator did not approve closure signing in time".into()),
        }
    }
    match client.exchange(&Request::CheckClosureSigningRequest {
        request_id: request.id.clone(),
    }) {
        Ok(Response::Success) => {}
        Ok(Response::Error { message }) => return deny(message),
        _ => return deny("closure signing requester disconnected".into()),
    }
    let latest = (|| {
        let path = SecretPath::parse(&signing.identifier).map_err(|e| e.to_string())?;
        let record = client
            .get(&path)
            .map_err(|e| e.to_string())?
            .ok_or("Nix signing key was removed during approval")?;
        let (_, _, hash) = public_envelope(
            record
                .public_key
                .as_deref()
                .ok_or("Nix signing key lost its public half")?,
        )?;
        if hash != signing.public_key_sha256 {
            return Err("Nix signing public key changed during approval".into());
        }
        Ok(())
    })();
    if let Err(error) = latest {
        return deny(error);
    }
    match batch.decrypt(provider).and_then(|mut values| {
        sign(
            &signing.manifest,
            &values
                .remove(&signing.identifier)
                .ok_or("missing Nix signing key")?,
            &name,
            &public,
        )
    }) {
        Ok(signatures) => (
            SecretAnswer::ClosureSigned { signatures },
            ChannelEvent::ArtifactSignatureFinished {
                requester: label,
                result: Ok(()),
            },
        ),
        Err(e) => deny(e),
    }
}

pub fn run(arguments: Vec<OsString>, runtime: &Path) -> Result<(), String> {
    let mut options = crate::with_secrets::Options {
        reason: None,
        ..Default::default()
    };
    let mut identifier = None;
    let mut host = None;
    let mut args = arguments.into_iter();
    while let Some(arg) = args.next() {
        let text = arg.to_str().ok_or("sign-closure arguments must be UTF8")?;
        if text == "--host" {
            host = Some(
                args.next()
                    .ok_or("--host requires name")?
                    .into_string()
                    .map_err(|_| "host must be UTF8")?,
            );
        } else if crate::with_secrets::parse_option(text, &mut args, &mut options)? {
        } else if text.starts_with('-') || identifier.is_some() {
            return Err(
                "usage: nix-secrets sign-closure --host HOST --reason TEXT IDENTIFIER".into(),
            );
        } else {
            identifier = Some(text.to_owned());
        }
    }
    if options.local
        || options.identity.is_some()
        || options.shared_session
        || options.schema_file.is_some()
    {
        return Err("closure signing only runs in the attached TUI".into());
    }
    crate::with_secrets::check_options(&options)?;
    let identifier = identifier.ok_or("sign-closure requires identifier")?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err("closure metadata exceeds bound".into());
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut stream =
        crate::with_secrets::connect_backend(&options, runtime).map_err(|e| e.to_string())?;
    let mut client = BackendClient::new(stream.try_clone().map_err(|e| e.to_string())?);
    let path = SecretPath::parse(&identifier).map_err(|e| e.to_string())?;
    let record = client
        .get(&path)
        .map_err(|e| e.to_string())?
        .ok_or("Nix signing key is unset")?;
    let (_, _, public_key_sha256) = public_envelope(
        record
            .public_key
            .as_deref()
            .ok_or("Nix signing key has no public half")?,
    )?;
    let request = SigningRequest {
        identifier,
        host: host.ok_or("--host required")?,
        public_key_sha256,
        manifest,
    };
    request.validate()?;
    nix_secrets_core::framing::write_json(
        &mut stream,
        &Request::RequestClosureSignatures {
            request,
            reason: options.reason,
        },
    )
    .map_err(|e| e.to_string())?;
    match nix_secrets_core::framing::read_json::<Response>(&mut stream)
        .map_err(|e| e.to_string())?
    {
        Some(Response::ClosureSignatures { signatures }) => {
            serde_json::to_writer(std::io::stdout(), &signatures).map_err(|e| e.to_string())
        }
        Some(Response::Error { message }) => Err(message),
        _ => Err("backend did not return closure signatures".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_secrets_core::closure_signing::ManifestPath;
    fn manifest() -> Manifest {
        Manifest {
            version: 1,
            paths: vec![ManifestPath {
                path: format!("/nix/store/{}-system", "0".repeat(32)),
                nar_hash: format!("sha256:{}", "0".repeat(52)),
                nar_size: 1024,
                references: vec![],
            }],
        }
    }
    #[test]
    fn signs_standard_nix_fingerprint_and_refuses_private_public_mismatch() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let secret = Zeroizing::new(format!(
            "host-update:{}\n",
            STANDARD.encode(key.to_keypair_bytes())
        ));
        let public = key.verifying_key().to_bytes();
        let batch = manifest();
        let signed = sign(&batch, secret.as_bytes(), "host-update", &public).unwrap();
        let (name, encoded) = signed.signatures[0].signature.split_once(':').unwrap();
        assert_eq!(name, "host-update");
        let bytes = STANDARD.decode(encoded).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&bytes).unwrap();
        key.verifying_key()
            .verify_strict(batch.paths[0].fingerprint().as_bytes(), &signature)
            .unwrap();
        assert!(key
            .verifying_key()
            .verify_strict(b"changed fingerprint", &signature)
            .is_err());
        assert!(sign(&batch, secret.as_bytes(), "other-name", &public).is_err());
        assert!(sign(&batch, secret.as_bytes(), "host-update", &[0; 32]).is_err());
        let mut inconsistent = key.to_keypair_bytes();
        inconsistent[63] ^= 1;
        let malformed = Zeroizing::new(format!("host-update:{}", STANDARD.encode(inconsistent)));
        assert!(sign(&batch, malformed.as_bytes(), "host-update", &public).is_err());
    }
    #[test]
    fn public_envelope_hash_binds_name_and_record_bytes() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let line = format!(
            "host-update:{}\n",
            STANDARD.encode(key.verifying_key().to_bytes())
        );
        let (name, public, hash) = public_envelope(&STANDARD.encode(&line)).unwrap();
        assert_eq!(name, "host-update");
        assert_eq!(public, key.verifying_key().to_bytes());
        assert_eq!(hash, format!("{:x}", Sha256::digest(line.as_bytes())));
        assert!(parse_named(b"bad name:AAAA").is_err());
        assert!(parse_named(b"key:AAAA\nextra").is_err());
    }
}
