#![forbid(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use nix_secrets_crypto::{
    AgeCommandProvider, CryptoError, Recipient, decrypt_secret, encrypt_secret,
};

const IDENTIFIER: &str = "test-host.services.database.password";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        for _ in 0..16 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).expect("operating-system randomness");
            let suffix = random.map(|byte| format!("{byte:02x}")).concat();
            let path = env::temp_dir().join(format!("nix-secrets-age-{suffix}"));
            if fs::create_dir(&path).is_ok() {
                return Self(path);
            }
        }
        panic!("could not create an isolated test directory");
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tool_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn generate_identity(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");
}

fn public_key(private_key: &Path) -> String {
    fs::read_to_string(private_key.with_extension("pub"))
        .expect("read generated public key")
        .trim()
        .to_owned()
}

#[test]
fn real_age_identity_roundtrip_rejects_wrong_key_and_tampering() {
    let missing: Vec<_> = ["age", "ssh-keygen"]
        .into_iter()
        .filter(|program| !tool_available(program))
        .collect();
    if !missing.is_empty() {
        panic!(
            "required real-age tools are missing: {}; run this test through the flake check",
            missing.join(", ")
        );
    }

    let directory = TestDirectory::create();
    let identity = directory.0.join("identity");
    let wrong_identity = directory.0.join("wrong-identity");
    generate_identity(&identity);
    generate_identity(&wrong_identity);

    let public_key = public_key(&identity);
    let recipient = Recipient {
        id: "test-ed25519-key",
        ssh_public_key: &public_key,
    };
    let provider = AgeCommandProvider::identity_file(&identity);
    let secret = b"real age secret\0with binary";
    let record = encrypt_secret(IDENTIFIER, secret, &[recipient], &provider).unwrap();
    assert_eq!(
        &*decrypt_secret(IDENTIFIER, &record, &provider).unwrap(),
        secret
    );

    let wrong_provider = AgeCommandProvider::identity_file(&wrong_identity);
    assert!(matches!(
        decrypt_secret(IDENTIFIER, &record, &wrong_provider),
        Err(CryptoError::AgeFailed(_))
    ));

    let mut tampered = record;
    let last = tampered
        .age_ciphertext
        .last_mut()
        .expect("nonempty ciphertext");
    *last ^= 1;
    assert!(matches!(
        decrypt_secret(IDENTIFIER, &tampered, &provider),
        Err(CryptoError::AgeFailed(_))
    ));
}
