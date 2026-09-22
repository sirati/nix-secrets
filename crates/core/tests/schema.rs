mod common;

use nix_secrets_core::{
    ByteEncoding, GeneratedSecretType, GenerationPolicy, LeafSpec, Schema, SchemaError, SecretPath,
};
use serde_json::json;

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";

#[test]
fn parses_normalized_nix_inventory() {
    let spec = common::schema().secret(&common::path()).unwrap();
    assert_eq!(spec.recipient_public_keys, ["ssh-ed25519 test"]);
    assert_eq!(
        spec.destination.path,
        "/persistent/secrets/mail/service/password"
    );
    assert_eq!(spec.consumer_units, ["mail.service"]);
}

#[test]
fn rejects_ambiguous_or_traversing_paths() {
    assert!(matches!(
        SecretPath::parse("host.services.mail"),
        Err(SchemaError::TooShort)
    ));
    assert!(matches!(
        SecretPath::parse("host.services...password"),
        Err(SchemaError::InvalidComponent(_))
    ));
    assert!(matches!(
        SecretPath::new(["host", "services", "..", "password"].map(str::to_owned)),
        Err(SchemaError::InvalidComponent(_))
    ));
}

#[test]
fn rejects_unknown_schema_path() {
    let path = SecretPath::parse("host.services.mail.unknown").unwrap();
    assert!(matches!(
        common::schema().secret(&path),
        Err(SchemaError::NotFound(_))
    ));
}

#[test]
fn parses_and_looks_up_generated_secret() {
    let schema = Schema::from_json(&generated_schema(23, vec![KEY], None)).unwrap();
    let path = SecretPath::parse("host.services.backup.storage-key").unwrap();
    let spec = schema.generated_secret(&path).unwrap();
    assert!(matches!(
        spec.generated_secret.secret_type,
        GeneratedSecretType::StorageBoxSshKey
    ));
    assert_eq!(spec.generated_secret.bootstrap.port, 23);
    assert_eq!(
        spec.generated_secret.output.path,
        "/persistent/secrets/backup/backup/storage-key"
    );
    assert!(matches!(
        schema.leaf(&path).unwrap(),
        LeafSpec::Generated(_)
    ));
    assert!(matches!(
        schema.secret(&path),
        Err(SchemaError::WrongKind(_))
    ));
}

#[test]
fn rejects_invalid_generated_secret_boundaries() {
    assert!(Schema::from_json(&generated_schema(22, vec![KEY], None)).is_err());
    assert!(Schema::from_json(&generated_schema(23, vec!["ssh-ed25519 invalid"], None)).is_err());
    assert!(Schema::from_json(&generated_schema(23, vec![KEY, KEY], None)).is_err());
    assert!(Schema::from_json(&generated_schema(23, vec![KEY], Some(true))).is_err());
}

#[test]
fn generated_task_input_accepts_generation_policy() {
    let mut value: serde_json::Value =
        serde_json::from_str(&generated_schema(23, vec![KEY], None)).unwrap();
    value["host"]["services"]["backup"]["storage-key"]["generation"] = json!({
        "type": "random-bytes", "bytes": 32, "encoding": "base64url-unpadded"
    });
    let schema = Schema::from_json(&value.to_string()).unwrap();
    let path = SecretPath::parse("host.services.backup.storage-key").unwrap();
    assert_eq!(
        schema.generated_secret(&path).unwrap().generation,
        Some(GenerationPolicy::RandomBytes {
            bytes: 32,
            encoding: ByteEncoding::Base64urlUnpadded,
        })
    );
}

fn generated_schema(port: u16, host_keys: Vec<&str>, unknown: Option<bool>) -> String {
    let mut generated = json!({
        "type": "storage-box-ssh-key",
        "output": {
            "path": "/persistent/secrets/backup/backup/storage-key",
            "category": "backup",
            "owner": "backup",
            "group": "backup",
            "mode": "0400"
        },
        "bootstrap": {
            "host": "u123.storagebox.example",
            "port": port,
            "user": "u123",
            "hostPublicKeys": host_keys
        }
    });
    if unknown.is_some() {
        generated["unknown"] = json!(true);
    }
    json!({
        "host": {
            "metadata": {
                "socketPath": "/run/nix-secrets/backend.sock",
                "deployment": { "host": "host", "destination": "update@host", "port": 22 }
            },
            "services": { "backup": { "storage-key": {
                "kind": "generated",
                "recipientPublicKeys": [KEY],
                "recipientIds": ["recipient-id"],
                "generatedSecret": generated,
                "consumerUnits": ["backup.service"]
            }}}
        }
    })
    .to_string()
}
