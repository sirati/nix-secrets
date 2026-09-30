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
    assert!(validate_ssh_known_hosts(&valid, &["box.example"], 23).is_ok());
    for value in [
        format!("[other.example]:23 ssh-ed25519 {key}"),
        format!("[box.example]:22 ssh-ed25519 {key}"),
        format!("*.example ssh-ed25519 {key}"),
        format!("@revoked [box.example]:23 ssh-ed25519 {key}"),
        format!("[box.example]:23 ssh-ed25519 {key}\n[box.example]:23 ssh-ed25519 {key}"),
        format!("[box.example]:23  ssh-ed25519 {key}"),
    ] {
        assert!(
            validate_ssh_known_hosts(&value, &["box.example"], 23).is_err(),
            "accepted {value:?}"
        );
    }
}

#[test]
fn public_known_hosts_accepts_several_hosts_and_key_types() {
    use nix_secrets_core::schema::{known_hosts_keys, validate_ssh_known_hosts};
    let key = KEY.split_ascii_whitespace().nth(1).unwrap();
    let rsa = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDfkeXdz7vYJcdhsniWhb8JWLd+//q+vYgJyJVU3nLMyp3DClVa31YTkQsM9+wLv9KqwIJpHpTPzJzpV5YqmsZFrjwnL9K1BZScifNcKxFYuAq9KYzhW+OKJHEr1CnqocwD2evN6FcNq5m7imWCvC1PuGamVGhU9Yrvqgbi6MP0GQ==";
    let hosts = ["sub1.box.example", "sub2.box.example"];
    let value = format!(
        "[sub1.box.example]:23 ssh-ed25519 {key}\n[sub1.box.example]:23 ssh-rsa {rsa}\n[sub2.box.example]:23 ssh-ed25519 {key}\n"
    );
    {
        validate_ssh_known_hosts(&value, &hosts, 23).unwrap();
        assert_eq!(
            known_hosts_keys(&value, &hosts, 23, "sub1.box.example").unwrap(),
            [format!("ssh-ed25519 {key}"), format!("ssh-rsa {rsa}")]
        );
        assert!(validate_ssh_known_hosts(&value, &["sub1.box.example"], 23).is_err());
    }
    let repeated = format!("[sub1.box.example]:23 ssh-ed25519 {key}\n[sub1.box.example]:23 ssh-ed25519 {key}\n");
    assert!(validate_ssh_known_hosts(&repeated, &hosts, 23).is_err());
}

#[test]
fn a_public_default_value_must_match_the_declared_hosts() {
    let key = KEY.split_ascii_whitespace().nth(1).unwrap();
    let schema = |default: &str| {
        serde_json::json!({"host": {
            "metadata": {"socketPath": "/run/nix-secrets/backend.sock",
                "deployment": {"host": "host", "destination": "secrets@host", "port": 22}},
            "services": {"backup-public-info": {"storage-box-known-hosts": {
                "kind": "public-info", "sharedPublicId": "storage-box/known-hosts",
                "expectedSshHost": "box.example", "expectedSshHosts": ["sub1.box.example"],
                "expectedSshPort": 23, "installDefaultIfMissing": true,
                "defaultValue": default, "consumerUnits": [],
                "destination": {"path": "/persistent/public-info/storage-box/known-hosts",
                    "category": "public-info", "owner": "root", "group": "root",
                    "mode": "0644", "contentType": "ssh-known-hosts"}}}}
        }})
        .to_string()
    };
    let good = format!("[box.example]:23 ssh-ed25519 {key}\n[sub1.box.example]:23 ssh-ed25519 {key}\n");
    let parsed = nix_secrets_core::Schema::from_json(&schema(&good)).unwrap();
    let path = nix_secrets_core::SecretPath::parse(
        "host.services.backup-public-info.storage-box-known-hosts",
    )
    .unwrap();
    let spec = parsed.secret(&path).unwrap();
    assert_eq!(spec.default_value.as_deref(), Some(good.as_str()));
    assert_eq!(spec.ssh_hosts(), ["box.example", "sub1.box.example"]);
    let other = format!("[sub2.box.example]:23 ssh-ed25519 {key}\n");
    assert!(nix_secrets_core::Schema::from_json(&schema(&other)).is_err());
}

#[test]
fn optional_deployed_leaf_is_preserved_and_cannot_be_required_for_install() {
    let mut document = serde_json::to_value(common::schema()).unwrap();
    document["host"]["services"]["mail"]["password"]["optional"] = json!(true);
    let schema = Schema::from_json(&document.to_string()).unwrap();
    assert!(schema.secret(&SecretPath::parse("host.services.mail.password").unwrap()).unwrap().optional);
    document["host"]["services"]["mail"]["password"]["requiredForInstall"] = json!(true);
    assert!(Schema::from_json(&document.to_string()).is_err());
}
