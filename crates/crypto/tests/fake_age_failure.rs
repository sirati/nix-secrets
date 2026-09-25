//! A failing age must yield a readable, attributed, secret-free report.
use std::{env, fs, os::unix::fs::PermissionsExt, path::PathBuf};

use nix_secrets_crypto::{
    AgeCommandProvider, EncryptedSecret, Recipient, decrypt_secret, encrypt_secret,
};

const IDENTIFIER: &str = "host.services.mail.password";

struct Scripts(PathBuf);

impl Scripts {
    fn new() -> Self {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let suffix = random.map(|byte| format!("{byte:02x}")).concat();
        let path = env::temp_dir().join(format!("nix-secrets-fake-age-{suffix}"));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

impl Drop for Scripts {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn record() -> EncryptedSecret {
    EncryptedSecret {
        format_version: 1,
        version_id: vec![7; 16],
        recipient_ids: vec!["operator".into()],
        age_ciphertext: b"age-encryption.org/v1\n".to_vec(),
    }
}

#[test]
fn one_password_plugin_failure_reports_op_message_and_hint() {
    let scripts = Scripts::new();
    let age = scripts.script(
        "age",
        "cat >/dev/null\n\
         echo 'age: error: 1p plugin: failed to get SSH keys from 1Password: exit status 1' >&2\n\
         echo 'age: report unexpected or unhelpful errors at https://filippo.io/age/report' >&2\n\
         exit 1",
    );
    let op = scripts.script(
        "op",
        "echo \"[ERROR] 2026/09/25 14:18:04 connecting to desktop app: read: connection reset, \
         make sure 1Password CLI is installed correctly\" >&2\nexit 1",
    );
    let provider = AgeCommandProvider::new(&age).with_one_password_cli(&op);
    let error = decrypt_secret(IDENTIFIER, &record(), &provider)
        .unwrap_err()
        .to_string();
    let expected = format!(
        "decrypting host.services.mail.password failed: age exited with exit code 1: \
         age: error: 1p plugin: failed to get SSH keys from 1Password: exit status 1\n\
         op ({op}): connecting to desktop app: read: connection reset, make sure 1Password CLI \
         is installed correctly\n\
         Hint: the 1Password app rejected {op}; it accepts only an op that is setgid \
         onepassword-cli. On NixOS enable programs._1password so /run/wrappers/bin/op exists \
         and precedes other op binaries in PATH",
        op = op.display()
    );
    assert_eq!(error, expected);
    assert!(!error.contains("Some("));
}

#[test]
fn encryption_failure_names_recipients_and_never_echoes_plaintext() {
    let scripts = Scripts::new();
    let age = scripts.script(
        "age",
        "cat >/dev/null\necho 'age: error: malformed SSH recipient' >&2\nexit 3",
    );
    let provider = AgeCommandProvider::new(&age);
    let recipients = [Recipient {
        id: "SHA256:operator",
        ssh_public_key: "ssh-ed25519 AAAAoperator",
    }];
    let error = encrypt_secret(IDENTIFIER, b"hunter2-plaintext", &recipients, &provider)
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "encrypting host.services.mail.password for recipients SHA256:operator failed: \
         age exited with exit code 3: age: error: malformed SSH recipient"
    );
    assert!(!error.contains("hunter2"));
}
