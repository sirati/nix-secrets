#![allow(dead_code)]

use nix_secrets_core::{EncryptedSecret, Schema, SecretPath};

pub fn schema() -> Schema {
    Schema::from_json(r#"{
        "host": {
            "metadata": { "socketPath": "/run/nix-secrets/backend.sock", "deployment": { "host": "host", "destination": "nix-secrets-forward@host", "port": 22 } },
            "services": {
                "mail": {
                    "password": {
                        "recipientPublicKeys": ["ssh-ed25519 test"],
                        "recipientIds": ["recipient-id"],
                        "destination": {
                            "path": "/persistent/secrets/mail/service/password",
                            "category": "service",
                            "owner": "mail",
                            "group": "mail",
                            "mode": "0400"
                        },
                        "consumerUnits": ["mail.service"]
                    }
                }
            },
            "user-alice-services": {}
        }
    }"#).unwrap()
}

pub fn path() -> SecretPath {
    SecretPath::parse("host.services.mail.password").unwrap()
}

pub fn envelope(value: &str) -> EncryptedSecret {
    EncryptedSecret {
        format_version: 1,
        version_id: [value.len() as u8; 16].to_vec(),
        recipient_ids: vec!["recipient-id".into()],
        age_ciphertext: format!("age-file-{value}").into_bytes(),
    }
}
