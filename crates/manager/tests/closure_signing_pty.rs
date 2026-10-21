//! Actual ratatui terminal and production backend: a closure approval whose
//! fingerprints list hundreds of references stays readable in a real PTY.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use nix_secrets_core::{
    closure_signing::{Manifest, ManifestPath},
    EncryptedSecret, Schema, SecretPath, SecretStore,
};
use nix_secrets_crypto::{encrypt_secret, AgeCommandProvider, Recipient};
use std::{fs, process::Command};

fn store(name: &str, index: usize) -> String {
    let hash = format!("{index:032}");
    format!("/nix/store/{hash}-{name}")
}

#[test]
fn production_terminal_shows_a_tall_closure_approval_whole() {
    let (Ok(python), Ok(backend)) = (
        std::env::var("NIX_SECRETS_PYTE_PYTHON"),
        std::env::var("NIX_SECRETS_TEST_BACKEND"),
    ) else {
        eprintln!(
            "actual PTY regression requires pyte Python and production backend binary; not run"
        );
        return;
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
    let identifier = "ns1.services.system-update.signing-key";
    let schema_json = serde_json::json!({"ns1":{"metadata":{"socketPath":"/run/unused-fixture-forwarder","deployment":{"host":"ns1","destination":"forward@ns1","port":22}},"services":{"system-update":{"signing-key":{"kind":"operator","signingOnly":true,"generator":{"installable":"trusted-test#nix-key","args":[]},"recipientPublicKeys":[recipient.trim()],"recipientIds":["operator"]}}}}});
    fs::write(root.path().join("schema.json"), schema_json.to_string()).unwrap();
    let schema = Schema::from_json(&schema_json.to_string()).unwrap();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let private = format!(
        "ns1-system-update:{}\n",
        STANDARD.encode(key.to_keypair_bytes())
    );
    let public = format!(
        "ns1-system-update:{}\n",
        STANDARD.encode(key.verifying_key().to_bytes())
    );
    let encrypted = encrypt_secret(
        identifier,
        private.as_bytes(),
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
                public_key: Some(STANDARD.encode(public)),
            },
        )
        .unwrap();
    // A system update: the system path and the unit directory each
    // reference hundreds of paths, so their fingerprints wrap to dozens
    // of rows and the dialog outgrows a 240-row terminal.
    let references = |name: &str, count: usize| {
        let mut all = (0..count)
            .map(|index| store(&format!("{name}-{index}"), index))
            .collect::<Vec<_>>();
        all.sort();
        all
    };
    let mut paths = vec![
        ManifestPath {
            path: store("system-path", 1),
            nar_hash: format!("sha256:{}", "0".repeat(52)),
            nar_size: 5811728,
            references: references("package", 300),
        },
        ManifestPath {
            path: store("system-units", 2),
            nar_hash: format!("sha256:{}", "1".repeat(52)),
            nar_size: 81234,
            references: references("unit-lifecycle-probe.service", 400),
        },
    ];
    for index in 3..21 {
        paths.push(ManifestPath {
            path: store(&format!("update-{index}"), index),
            nar_hash: format!("sha256:{}", "1".repeat(52)),
            nar_size: 1490648,
            references: references("dependency", 6),
        });
    }
    paths.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = Manifest { version: 1, paths };
    let config = root.path().join("pty-config.json");
    fs::write(&config, serde_json::json!({"root":root.path(), "frontend":std::env::var("NIX_SECRETS_TEST_FRONTEND").unwrap_or_else(|_| env!("CARGO_BIN_EXE_nix-secrets").into()), "backend":backend, "identifier":identifier, "reason":"Sign the standard Nix closure metadata for the system update of ns1.", "manifest":manifest}).to_string()).unwrap();
    let result = Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pty/closure_approval.py"
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
}
