mod common;

use nix_secrets_core::{ConsumerConstraints, Schema, SchemaError, ValueType};
use serde_json::{Value, json};

#[test]
fn password_leaf_exposes_consumer_limits() {
    let schema = schema_with(json!({
        "valueType": "password",
        "consumerConstraints": {
            "cannotHandleShorterThan": 8,
            "cannotHandleLongerThan": 64,
            "matchingRegex": "[A-Za-z0-9]+"
        }
    }))
    .unwrap();
    let leaf = schema.secret(&common::path()).unwrap();
    assert_eq!(leaf.value_type, Some(ValueType::Password));
    assert_eq!(
        leaf.consumer_constraints,
        Some(ConsumerConstraints {
            cannot_handle_shorter_than: Some(8),
            cannot_handle_longer_than: Some(64),
            matching_regex: Some("[A-Za-z0-9]+".into()),
        })
    );
}

#[test]
fn key_leaf_exposes_explicit_type_and_description() {
    let schema = schema_with(json!({
        "valueType": "key", "description": "Operator SSH public key", "humanFacing": true,
        "destination": {
            "path": "/persistent/secrets/mail/service/password", "category": "service",
            "owner": "mail", "group": "mail", "mode": "0400",
            "contentType": "openssh-public-key"
        }
    }))
    .unwrap();
    let leaf = schema.secret(&common::path()).unwrap();
    assert_eq!(leaf.value_type, Some(ValueType::Key));
    assert_eq!(leaf.description.as_deref(), Some("Operator SSH public key"));
    assert!(leaf.human_facing);
}

#[test]
fn rejects_invalid_consumer_limits() {
    for leaf in [
        json!({ "consumerConstraints": { "cannotHandleShorterThan": 8 } }),
        json!({ "valueType": "password", "consumerConstraints": {
            "cannotHandleShorterThan": 65, "cannotHandleLongerThan": 64
        }}),
        json!({ "valueType": "password", "consumerConstraints": {
            "matchingRegex": "["
        }}),
    ] {
        assert!(matches!(
            schema_with(leaf),
            Err(nix_secrets_core::SchemaLoadError::Schema(
                SchemaError::InvalidValueDefinition(_, _)
            ))
        ));
    }
    assert!(
        schema_with(json!({ "valueType": "password", "generation": {
            "type": "random-password", "length": 32
        }}))
        .is_err()
    );
}

#[test]
fn consumer_limits_match_entire_value() {
    let limits = ConsumerConstraints {
        cannot_handle_shorter_than: Some(3),
        cannot_handle_longer_than: Some(5),
        matching_regex: Some("[a-z]+".into()),
    };
    assert!(limits.accepts("abc").is_ok());
    assert!(limits.accepts("ab").is_err());
    assert!(limits.accepts("abcdef").is_err());
    assert!(limits.accepts("abc1").is_err());
}

fn schema_with(leaf: Value) -> Result<Schema, nix_secrets_core::SchemaLoadError> {
    let mut schema: Value = serde_json::from_str(&common::schema_json()).unwrap();
    let leaf_map = schema["host"]["services"]["mail"]["password"]
        .as_object_mut()
        .unwrap();
    leaf_map.extend(leaf.as_object().unwrap().clone());
    Schema::from_json(&schema.to_string())
}
