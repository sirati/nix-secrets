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
        // Written under another name and renamed: executing a file that a
        // parallel test thread still holds open for writing fails with ETXTBSY.
        let staging = self.0.join(format!(".{name}.tmp"));
        fs::write(&staging, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&staging, &path).unwrap();
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

#[test]
fn decryption_runs_through_the_launcher_but_encryption_does_not() {
    let scripts = Scripts::new();
    let log = scripts.0.join("calls");
    let age = scripts.script(
        "age",
        &format!(
            "echo \"age $1\" >> {log}\ncat >/dev/null\nexit 1",
            log = log.display()
        ),
    );
    let launcher = scripts.script(
        "launcher",
        &format!(
            "echo \"launcher $2\" >> {log}\nshift\nexec \"$@\"",
            log = log.display()
        ),
    );
    let provider = AgeCommandProvider::new(&age).through(&launcher, vec!["--flag".into()]);
    let _ = decrypt_secret(IDENTIFIER, &record(), &provider);
    let recipients = [Recipient {
        id: "operator",
        ssh_public_key: "ssh-ed25519 AAAAoperator",
    }];
    let _ = encrypt_secret(IDENTIFIER, b"x", &recipients, &provider);
    assert_eq!(
        fs::read_to_string(&log).unwrap(),
        format!("launcher {}\nage --decrypt\nage --encrypt\n", age.display())
    );
}

#[test]
fn launcher_authorization_failure_reads_as_denied_without_probing_op() {
    let scripts = Scripts::new();
    let age = scripts.script("age", "exit 0");
    let launcher = scripts.script(
        "launcher",
        "cat >/dev/null\necho 'nix-secrets-1password: 1Password authorization failed: \
         authorization prompt dismissed, please try again' >&2\nexit 77",
    );
    let calls = scripts.0.join("op-calls");
    let op = scripts.script("op", &format!("echo \"$*\" >> {}", calls.display()));
    let provider = AgeCommandProvider::new(&age)
        .with_one_password_cli(&op)
        .through(&launcher, vec![]);
    let error = decrypt_secret(IDENTIFIER, &record(), &provider)
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "decrypting host.services.mail.password failed: 1Password authorization denied or \
         failed: authorization prompt dismissed, please try again\n\
         Hint: approve the 1Password authorization prompt and retry"
    );
    assert!(!calls.exists(), "no op call after a denial");
}
