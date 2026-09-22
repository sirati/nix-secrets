mod common;

use nix_secrets_core::{SecretPath, SecretStore, StoreError};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::thread;

#[test]
fn writes_atomically_with_private_mode() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nix-secrets.toml");
    let store = SecretStore::new(&path);
    store
        .set(&common::schema(), &common::path(), common::envelope("one"))
        .unwrap();
    assert_eq!(
        store.get(&common::path()).unwrap(),
        Some(common::envelope("one"))
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let serialized = std::fs::read_to_string(path).unwrap();
    assert!(serialized.contains("age_ciphertext"));
    assert!(serialized.contains("host.services.mail.password"));
    assert!(!serialized.contains("age-file-one"));
}

#[test]
fn concurrent_updates_do_not_lose_entries() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(SecretStore::new(directory.path().join("nix-secrets.toml")));
    let schema = Arc::new(schema_with_many_secrets(24));
    let threads: Vec<_> = (0..24)
        .map(|index| {
            let store = Arc::clone(&store);
            let schema = Arc::clone(&schema);
            thread::spawn(move || {
                let path = SecretPath::parse(&format!("host.services.app.secret_{index}")).unwrap();
                store
                    .set(&schema, &path, common::envelope(&index.to_string()))
                    .unwrap();
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(store.list().unwrap().len(), 24);
}

#[test]
fn replacement_keeps_the_canonical_identifier_and_resolution() {
    let directory = tempfile::tempdir().unwrap();
    let store = SecretStore::new(directory.path().join("nix-secrets.toml"));
    let schema = common::schema();
    let identifier = common::path();
    let destination = schema.secret(&identifier).unwrap().destination.path;
    let first = common::envelope("first");
    let replacement = common::envelope("replacement");
    assert_ne!(first.version_id, replacement.version_id);

    store.set(&schema, &identifier, first).unwrap();
    store
        .set(&schema, &identifier, replacement.clone())
        .unwrap();

    assert_eq!(store.get(&identifier).unwrap(), Some(replacement));
    assert_eq!(
        schema.secret(&identifier).unwrap().destination.path,
        destination
    );
    assert_eq!(identifier.to_string(), "host.services.mail.password");
}

#[test]
fn validates_recipient_before_writing() {
    let directory = tempfile::tempdir().unwrap();
    let store = SecretStore::new(directory.path().join("nix-secrets.toml"));
    let mut envelope = common::envelope("bad");
    envelope.recipient_ids = vec!["other".into()];
    assert!(matches!(
        store.set(&common::schema(), &common::path(), envelope),
        Err(StoreError::RecipientMismatch)
    ));
}

#[test]
fn rejects_empty_age_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let store = SecretStore::new(directory.path().join("nix-secrets.toml"));
    let mut record = common::envelope("bad");
    record.age_ciphertext.clear();
    assert!(matches!(
        store.set(&common::schema(), &common::path(), record),
        Err(StoreError::InvalidRecord)
    ));
}

fn schema_with_many_secrets(count: usize) -> nix_secrets_core::Schema {
    let secrets = (0..count)
        .map(|index| {
            (
                format!("secret_{index}"),
                serde_json::json!({
                    "kind": "secret",
                    "recipientPublicKeys": ["ssh-ed25519 test"],
                    "recipientIds": ["recipient-id"],
                    "destination": {
                        "path": format!("/persistent/secrets/app/service/secret_{index}"),
                        "category": "service", "owner": "app", "group": "app", "mode": "0400"
                    },
                    "consumerUnits": ["app.service"]
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::from_value(serde_json::json!({
        "host": {
            "metadata": { "socketPath": "/run/nix-secrets/backend.sock", "deployment": { "host": "host", "destination": "nix-secrets-forward@host", "port": 22 } },
            "services": { "app": secrets }
        }
    })).unwrap()
}
