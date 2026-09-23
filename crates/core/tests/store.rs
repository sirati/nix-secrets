mod common;

use nix_secrets_core::{SecretPath, SecretStore, StoreError};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::thread;

const ED25519_PUBLIC: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f test";

#[test]
fn generated_public_metadata_is_cas_saved_and_read_back_without_a_private_sidecar() {
    use nix_secrets_core::GeneratedPublicKey;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nix-secrets.toml");
    let store = SecretStore::new(&path);
    let document = serde_json::json!({
        "host": {
            "metadata": {"socketPath":"/run/backend.sock", "deployment": {"host":"host", "destination":"forward@host", "port":22}},
            "services": {"backup": {"key": {
                "kind":"generated", "recipientPublicKeys":[ED25519_PUBLIC], "recipientIds":["recipient-id"],
                "generatedSecret":{"type":"local-ssh-key", "output":{"path":"/persistent/secrets/backup/service/key", "category":"service", "owner":"backup", "group":"backup", "mode":"0400", "contentType":"openssh-private-key"}, "bootstrap":null},
                "consumerUnits":[]
            }}}
        }
    });
    let schema = nix_secrets_core::Schema::from_json(&document.to_string()).unwrap();
    let identifier = SecretPath::parse("host.services.backup.key").unwrap();
    let metadata = GeneratedPublicKey {
        version_id: "v1".into(),
        public_key: ED25519_PUBLIC.into(),
    };
    store
        .set_generated_public_key_if_version(&schema, &identifier, metadata.clone(), None)
        .unwrap();
    assert_eq!(
        store.generated_public_key(&identifier).unwrap(),
        Some(metadata.clone())
    );
    assert!(matches!(
        store.set_generated_public_key_if_version(&schema, &identifier, metadata.clone(), None),
        Err(StoreError::VersionConflict)
    ));
    assert!(matches!(
        store.set_generated_public_key_if_version(
            &schema,
            &identifier,
            GeneratedPublicKey {
                version_id: "v2".into(),
                public_key: "ssh-ed25519 invalid".into()
            },
            Some("v1")
        ),
        Err(StoreError::InvalidPublicKey)
    ));
    let raw = std::fs::read_to_string(path).unwrap();
    assert!(raw.contains("generated_public_keys"));
    assert!(raw.contains("public_key"));
    assert!(!raw.contains("PRIVATE KEY"));
}

#[test]
fn named_recipients_deduplicate_ids_and_keep_old_revisions_readable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nix-secrets.toml");
    let store = SecretStore::new(&path);
    let mut document: serde_json::Value = serde_json::from_str(common::schema_json()).unwrap();
    let first = common::path();
    let old = common::envelope("old");
    store.set(&common::schema(), &first, old.clone()).unwrap();
    document["host"]["metadata"]["recipientPublicKeys"] =
        serde_json::json!({"primary": ED25519_PUBLIC});
    let leaf = document["host"]["services"]["mail"]["password"]
        .as_object_mut()
        .unwrap();
    leaf.insert("recipientNames".into(), serde_json::json!(["primary"]));
    leaf.insert(
        "recipientPublicKeys".into(),
        serde_json::json!([ED25519_PUBLIC]),
    );
    let mut second_leaf = document["host"]["services"]["mail"]["password"].clone();
    second_leaf["destination"]["path"] =
        serde_json::json!("/persistent/secrets/mail/service/other");
    document["host"]["services"]["mail"]["other"] = second_leaf;
    let schema = nix_secrets_core::Schema::from_json(&document.to_string()).unwrap();
    let second = SecretPath::parse("host.services.mail.other").unwrap();
    let mut new = common::envelope("new");
    new.version_id = vec![1; 16];
    store.set(&schema, &second, new.clone()).unwrap();
    assert_eq!(store.get(&first).unwrap(), Some(old));
    let stored = store.get(&second).unwrap().unwrap();
    assert_eq!(stored.recipient_ids, new.recipient_ids);
    assert_eq!(stored.recipient_refs, ["primary#0"]);
    let raw = std::fs::read_to_string(&path).unwrap();
    assert_eq!(raw.matches("primary#0").count(), 2); // one reference and one registry key
    assert_eq!(raw.matches("recipient_ids").count(), 1); // legacy record only

    document["host"]["metadata"]["recipientPublicKeys"]["primary"] = serde_json::json!(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8 rotated"
    );
    document["host"]["services"]["mail"]["password"]["recipientPublicKeys"] =
        serde_json::json!([document["host"]["metadata"]["recipientPublicKeys"]["primary"].clone()]);
    document["host"]["services"]["mail"]["other"]["recipientPublicKeys"] =
        document["host"]["services"]["mail"]["password"]["recipientPublicKeys"].clone();
    document["host"]["services"]["mail"]["password"]["recipientIds"] =
        serde_json::json!(["rotated-id"]);
    document["host"]["services"]["mail"]["other"]["recipientIds"] =
        serde_json::json!(["rotated-id"]);
    let rotated = nix_secrets_core::Schema::from_json(&document.to_string()).unwrap();
    let mut replacement = common::envelope("rotated");
    replacement.recipient_ids = vec!["rotated-id".into()];
    store.set(&rotated, &first, replacement).unwrap();
    assert_eq!(
        store.get(&second).unwrap().unwrap().recipient_ids,
        vec!["recipient-id"]
    );
    assert_eq!(
        store.get(&first).unwrap().unwrap().recipient_refs,
        ["primary#1"]
    );
}

#[test]
fn public_info_is_shared_across_hosts_and_replacement_is_atomic() {
    use nix_secrets_core::PublicInfoRecord;
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("nix-secrets.toml");
    let store = SecretStore::new(&file);
    let leaf = serde_json::json!({
        "kind":"public-info", "sharedPublicId":"storage-box/known-hosts",
        "expectedSshHost":"box.example", "expectedSshPort":23,
        "destination":{"path":"/persistent/public-info/storage-box/known-hosts", "category":"public-info", "owner":"root", "group":"root", "mode":"0644", "contentType":"ssh-known-hosts"},
        "consumerUnits":[]
    });
    let mut document = serde_json::json!({});
    for host in ["host-a", "host-b"] {
        document[host] = serde_json::json!({
            "metadata":{"socketPath":"/run/backend.sock", "deployment":{"host":host, "destination":format!("forward@{host}"), "port":22}},
            "services":{"backup":{"known-hosts":leaf}}
        });
    }
    let schema = nix_secrets_core::Schema::from_json(&document.to_string()).unwrap();
    let first = SecretPath::parse("host-a.services.backup.known-hosts").unwrap();
    let second = SecretPath::parse("host-b.services.backup.known-hosts").unwrap();
    let key = ED25519_PUBLIC.split_ascii_whitespace().nth(1).unwrap();
    let value = format!("[box.example]:23 ssh-ed25519 {key}\n");
    let initial = PublicInfoRecord {
        version_id: "01".repeat(16),
        value: value.clone(),
    };
    store
        .set_public_info_if_version(&schema, &first, initial.clone(), None)
        .unwrap();
    assert_eq!(
        store.get_public_info("storage-box/known-hosts").unwrap(),
        Some(initial.clone())
    );
    assert!(matches!(
        store.set_public_info_if_version(&schema, &second, initial.clone(), None),
        Err(StoreError::VersionConflict)
    ));
    let replacement = PublicInfoRecord {
        version_id: "02".repeat(16),
        value,
    };
    store
        .set_public_info_if_version(
            &schema,
            &second,
            replacement.clone(),
            Some(&initial.version_id),
        )
        .unwrap();
    assert_eq!(
        store.get_public_info("storage-box/known-hosts").unwrap(),
        Some(replacement)
    );
    let raw = std::fs::read_to_string(file).unwrap();
    assert_eq!(raw.matches("[box.example]:23").count(), 1);
    assert!(!raw.contains("age_ciphertext"));
}

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
fn conditional_set_rejects_stale_public_key_inventory() {
    let directory = tempfile::tempdir().unwrap();
    let store = SecretStore::new(directory.path().join("nix-secrets.toml"));
    let schema = common::schema();
    let path = common::path();
    let first = common::envelope("first");
    let second = common::envelope("second");
    let stale = common::envelope("stale");
    store
        .set_if_version(&schema, &path, first.clone(), None)
        .unwrap();
    assert!(matches!(
        store.set_if_version(&schema, &path, second.clone(), None),
        Err(StoreError::VersionConflict)
    ));
    store
        .set_if_version(&schema, &path, second.clone(), Some(&first.version_id))
        .unwrap();
    assert!(matches!(
        store.set_if_version(&schema, &path, stale, Some(&first.version_id)),
        Err(StoreError::VersionConflict)
    ));
    assert_eq!(store.get(&path).unwrap(), Some(second));
}

#[test]
fn conditional_delete_cannot_remove_a_newer_value() {
    let directory = tempfile::tempdir().unwrap();
    let store = SecretStore::new(directory.path().join("nix-secrets.toml"));
    let schema = common::schema();
    let path = common::path();
    let first = common::envelope("first");
    let second = common::envelope("second");
    store.set(&schema, &path, first.clone()).unwrap();
    store.set(&schema, &path, second.clone()).unwrap();
    assert!(matches!(
        store.remove_if_version(&schema, &path, &first.version_id),
        Err(StoreError::VersionConflict)
    ));
    assert_eq!(store.get(&path).unwrap(), Some(second.clone()));
    assert!(
        store
            .remove_if_version(&schema, &path, &second.version_id)
            .unwrap()
    );
    assert!(store.get(&path).unwrap().is_none());
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

#[test]
fn stores_and_removes_generated_task_input() {
    let directory = tempfile::tempdir().unwrap();
    let store = SecretStore::new(directory.path().join("nix-secrets.toml"));
    let schema = generated_schema();
    let path = SecretPath::parse("host.services.backup.storage-key").unwrap();
    let envelope = common::envelope("password");
    store.set(&schema, &path, envelope.clone()).unwrap();
    assert_eq!(store.get(&path).unwrap(), Some(envelope));
    assert!(store.remove(&schema, &path).unwrap());
}

fn generated_schema() -> nix_secrets_core::Schema {
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
    serde_json::from_value(serde_json::json!({
        "host": {
            "metadata": { "socketPath": "/run/nix-secrets/backend.sock", "deployment": { "host": "host", "destination": "update@host", "port": 22 } },
            "services": { "backup": { "storage-key": {
                "kind": "generated", "recipientPublicKeys": [KEY],
                "recipientIds": ["recipient-id"], "consumerUnits": [],
                "generatedSecret": {
                    "type": "storage-box-ssh-key",
                    "output": { "path": "/persistent/secrets/backup/backup/key", "category": "backup", "owner": "backup", "group": "backup", "mode": "0400" },
                    "bootstrap": { "host": "box.example", "port": 23, "user": "u1", "hostPublicKeys": [KEY] }
                }
            }}}
        }
    })).unwrap()
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
