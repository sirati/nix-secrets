mod common;

use nix_secrets_core::{GeneratedSecretType, LeafSpec, Schema, SchemaError, SecretPath, ValueType};
use serde_json::json;

#[test]
fn semantic_identity_resolves_legacy_storage_id_and_rejects_duplicates() {
    let mut document = serde_json::to_value(common::schema()).unwrap();
    let identity = json!({
        "host":"host", "scope":"system", "user":null,
        "service":"mail", "responsibility":"main", "namespace":"shared", "name":"password"
    });
    let leaf = &mut document["host"]["services"]["mail"]["password"];
    leaf["identity"] = identity.clone();
    leaf["presentation"] =
        json!({"explanation":"Mail login", "facing":"human", "type":"passphrase"});
    let schema = Schema::from_json(&document.to_string()).unwrap();
    let semantic = schema
        .secret(&SecretPath::parse("host.services.mail.password").unwrap())
        .unwrap()
        .identity
        .unwrap();
    assert_eq!(
        schema
            .resolve_identity(&semantic)
            .unwrap()
            .unwrap()
            .to_string(),
        "host.services.mail.password"
    );
    let mut invalid = document.clone();
    invalid["host"]["services"]["mail"]["password"]["presentation"]["explanation"] =
        json!("first line\nsecond line");
    assert!(
        matches!(Schema::from_json(&invalid.to_string()), Err(nix_secrets_core::SchemaLoadError::Schema(SchemaError::InvalidValueDefinition(_, message))) if message == "invalid presentation metadata")
    );
    let mut duplicate = document["host"]["services"]["mail"]["password"].clone();
    duplicate["destination"]["path"] = json!("/persistent/secrets/mail/service/second");
    document["host"]["services"]["mail"]["second"] = duplicate;
    assert!(
        matches!(Schema::from_json(&document.to_string()), Err(nix_secrets_core::SchemaLoadError::Schema(SchemaError::InvalidValueDefinition(_, message))) if message == "duplicate semantic identity")
    );
}

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
    assert_eq!(spec.generated_secret.bootstrap.as_ref().unwrap().port, 23);
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
fn generated_task_input_can_be_a_password() {
    let mut value: serde_json::Value =
        serde_json::from_str(&generated_schema(23, vec![KEY], None)).unwrap();
    value["host"]["services"]["backup"]["storage-key"]["valueType"] = json!("password");
    let schema = Schema::from_json(&value.to_string()).unwrap();
    let path = SecretPath::parse("host.services.backup.storage-key").unwrap();
    assert_eq!(
        schema.generated_secret(&path).unwrap().value_type,
        Some(ValueType::Password)
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

#[test]
fn public_known_hosts_rejects_wrong_hosts_ports_and_tofu_syntax() {
    use nix_secrets_core::schema::validate_ssh_known_hosts;
    let key = KEY.split_ascii_whitespace().nth(1).unwrap();
    let valid = format!("[box.example]:23 ssh-ed25519 {key}\n");
    assert!(validate_ssh_known_hosts(&valid, "box.example", 23).is_ok());
    for value in [
        format!("[other.example]:23 ssh-ed25519 {key}"),
        format!("[box.example]:22 ssh-ed25519 {key}"),
        format!("*.example ssh-ed25519 {key}"),
        format!("@revoked [box.example]:23 ssh-ed25519 {key}"),
        format!("[box.example]:23 ssh-ed25519 {key}\n[box.example]:23 ssh-ed25519 {key}"),
        format!("[box.example]:23  ssh-ed25519 {key}"),
    ] {
        assert!(
            validate_ssh_known_hosts(&value, "box.example", 23).is_err(),
            "accepted {value:?}"
        );
    }
}
