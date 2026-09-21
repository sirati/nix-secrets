mod common;

use nix_secrets_core::{SchemaError, SecretPath};

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
