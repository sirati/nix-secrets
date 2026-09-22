mod common;

use nix_secrets_core::{
    ByteEncoding, GenerationPolicy, PassphraseSeparator, PassphraseWordList, PasswordAlphabet,
    Schema, SchemaError,
};
use serde_json::{Value, json};

#[test]
fn accepts_every_generation_policy_on_stored_leaves() {
    let cases = [
        json!({ "type": "random-password", "length": 32, "alphabet": "ascii-safe" }),
        json!({
            "type": "random-passphrase", "words": 8,
            "separator": "hyphen", "wordList": "eff-large"
        }),
        json!({ "type": "random-bytes", "bytes": 32, "encoding": "base64url-unpadded" }),
    ];
    for policy in cases {
        let schema = schema_with_policy(policy);
        assert!(schema.is_ok(), "{schema:?}");
    }
}

#[test]
fn exposes_typed_policy_from_a_leaf() {
    let schema = schema_with_policy(json!({
        "type": "random-password", "length": 48, "alphabet": "alphanumeric"
    }))
    .unwrap();
    assert_eq!(
        schema.secret(&common::path()).unwrap().generation,
        Some(GenerationPolicy::RandomPassword {
            length: 48,
            alphabet: PasswordAlphabet::Alphanumeric,
        })
    );
}

#[test]
fn rejects_out_of_bounds_and_unknown_parameters() {
    for policy in [
        json!({ "type": "random-password", "length": 15, "alphabet": "ascii-safe" }),
        json!({
            "type": "random-passphrase", "words": 25,
            "separator": "space", "wordList": "eff-large"
        }),
        json!({ "type": "random-bytes", "bytes": 4097, "encoding": "hex" }),
    ] {
        assert!(matches!(
            schema_with_policy(policy),
            Err(nix_secrets_core::SchemaLoadError::Schema(
                SchemaError::InvalidGeneration(_)
            ))
        ));
    }
    assert!(
        schema_with_policy(json!({
            "type": "random-bytes", "bytes": 32,
            "encoding": "base64url-unpadded", "surprise": true
        }))
        .is_err()
    );
    assert!(
        schema_with_policy(json!({
            "type": "random-passphrase", "words": 8,
            "separator": "comma", "wordList": "eff-large"
        }))
        .is_err()
    );
}

#[test]
fn policy_enums_have_stable_wire_values() {
    assert_eq!(
        serde_json::to_value(GenerationPolicy::RandomBytes {
            bytes: 32,
            encoding: ByteEncoding::Base64urlUnpadded,
        })
        .unwrap(),
        json!({ "type": "random-bytes", "bytes": 32, "encoding": "base64url-unpadded" })
    );
    let _ = (
        PassphraseSeparator::Underscore,
        PassphraseWordList::EffLarge,
    );
}

fn schema_with_policy(policy: Value) -> Result<Schema, nix_secrets_core::SchemaLoadError> {
    let mut schema: Value = serde_json::from_str(&common::schema_json()).unwrap();
    schema["host"]["services"]["mail"]["password"]["generation"] = policy;
    Schema::from_json(&schema.to_string())
}
