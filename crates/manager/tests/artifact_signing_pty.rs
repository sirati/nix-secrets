//! Actual ratatui terminal, production daemon and local encrypted signing key.
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::{
    artifact_signing::{Artifact, Manifest, Signatures, REQUIRED_ROLES},
    EncryptedSecret, Schema, SecretPath, SecretStore,
};
use nix_secrets_crypto::{encrypt_secret, AgeCommandProvider, Recipient};
use nix_secrets_manager::keypair;
use sha2::{Digest, Sha512};
use std::{fs, process::Command};

#[test]
fn production_terminal_preserves_artifact_approval_during_noisy_schema_reload() {
    let (Ok(signer), Ok(python), Ok(backend)) = (
        std::env::var("NIX_SECRETS_ARTIFACT_SIGNER"),
        std::env::var("NIX_SECRETS_PYTE_PYTHON"),
        std::env::var("NIX_SECRETS_TEST_BACKEND"),
    ) else {
        eprintln!("actual PTY regression requires trusted signer, pyte Python and production backend binary; not run");
        return;
    };
    let artifact = std::env::var("NIX_SECRETS_SIGNING_TEST_ARTIFACT").unwrap_or_else(|_| {
        fs::canonicalize("/run/current-system/sw/bin/true")
            .unwrap()
            .to_str()
            .unwrap()
            .into()
    });
    let bytes = fs::read(&artifact).unwrap();
    let manifest = Manifest {
        artifacts: REQUIRED_ROLES
            .iter()
            .map(|role| Artifact {
                role: (*role).into(),
                path: artifact.clone(),
                sha512: format!("{:x}", Sha512::digest(&bytes)),
                size: bytes.len() as u64,
            })
            .collect(),
    };
    let root = tempfile::tempdir().unwrap();
    let identity = root.path().join("identity");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&identity)
        .status()
        .unwrap()
        .success());
    let recipient = fs::read_to_string(identity.with_extension("pub")).unwrap();
    let identifier = "host.services.nmbl.generation-key";
    let schema_json = serde_json::json!({"host":{"metadata":{"socketPath":"/run/unused-fixture-forwarder","deployment":{"host":"host","destination":"forward@host","port":22}},"services":{"nmbl":{"generation-key":{"kind":"operator","signingOnly":true,"generator":{"installable":"trusted-test#nmbl-sign","args":["keygen"]},"recipientPublicKeys":[recipient.trim()],"recipientIds":["operator"]}}}}});
    fs::write(root.path().join("schema.json"), schema_json.to_string()).unwrap();
    let schema = Schema::from_json(&schema_json.to_string()).unwrap();
    let pair = keypair::run(&[
        signer.clone().into(),
        "keygen".into(),
        "--alg".into(),
        "ml-dsa-65".into(),
        "--stdio".into(),
    ])
    .unwrap();
    let encrypted = encrypt_secret(
        identifier,
        &pair.private,
        &[Recipient {
            id: "operator",
            ssh_public_key: recipient.trim(),
        }],
        &AgeCommandProvider::identity_file(identity),
    )
    .unwrap();
    SecretStore::new(root.path().join("nix-secrets.toml"))
        .set(
            &schema,
            &SecretPath::parse(identifier).unwrap(),
            EncryptedSecret {
                format_version: encrypted.format_version,
                version_id: encrypted.version_id,
                recipient_ids: encrypted.recipient_ids,
                recipient_refs: vec![],
                age_ciphertext: encrypted.age_ciphertext,
                public_key: Some(STANDARD.encode(&pair.public)),
            },
        )
        .unwrap();
    let config = root.path().join("pty-config.json");
    fs::write(&config, serde_json::json!({"root":root.path(), "frontend":std::env::var("NIX_SECRETS_TEST_FRONTEND").unwrap_or_else(|_| env!("CARGO_BIN_EXE_nix-secrets").into()), "backend":backend, "identifier":identifier, "reason":"Sign host initial generation through verified client artifacts", "manifest":manifest}).to_string()).unwrap();
    let result = Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pty/artifact_approval.py"
        ))
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "actual PTY test failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let signatures: Signatures =
        serde_json::from_slice(&fs::read(root.path().join("signatures.json")).unwrap()).unwrap();
    signatures.validate(&manifest).unwrap();
    let public = root.path().join("public");
    fs::write(&public, &pair.public).unwrap();
    for signature in signatures.signatures {
        let sidecar = root.path().join(format!("{}.sig", signature.role));
        fs::write(
            &sidecar,
            STANDARD.decode(&signature.signature_base64).unwrap(),
        )
        .unwrap();
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
}
