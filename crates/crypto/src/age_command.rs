use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use zeroize::Zeroizing;

use crate::{
    CryptoError, CryptoProvider,
    secret::{MAX_CIPHERTEXT_SIZE, MAX_PLAINTEXT_SIZE},
};

/// Encrypts and decrypts whole secrets with age through anonymous pipes.
pub struct AgeCommandProvider {
    program: OsString,
    decryption: DecryptionMode,
}

enum DecryptionMode {
    OnePassword,
    IdentityFile(PathBuf),
}

impl Default for AgeCommandProvider {
    fn default() -> Self {
        Self {
            program: OsString::from("age"),
            decryption: DecryptionMode::OnePassword,
        }
    }
}

impl AgeCommandProvider {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            decryption: DecryptionMode::OnePassword,
        }
    }

    /// Uses an SSH private key supplied only at runtime to decrypt secrets.
    pub fn identity_file(identity: impl Into<PathBuf>) -> Self {
        Self::with_identity_file("age", identity)
    }

    /// Selects both the age executable and a runtime SSH identity file.
    pub fn with_identity_file(program: impl Into<OsString>, identity: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            decryption: DecryptionMode::IdentityFile(identity.into()),
        }
    }

    fn run(
        &self,
        arguments: &[OsString],
        input: &[u8],
        output_limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut child = Command::new(&self.program)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            CryptoError::AgeIo(std::io::Error::other("age stdin was not created"))
        })?;
        let mut stdout = child.stdout.take().ok_or_else(|| {
            CryptoError::AgeIo(std::io::Error::other("age stdout was not created"))
        })?;
        let input = Zeroizing::new(input.to_vec());
        let mut output = Zeroizing::new(Vec::with_capacity(output_limit.min(4096)));
        let (write_result, read_result) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || stdin.write_all(&input));
            let read = stdout
                .by_ref()
                .take((output_limit + 1) as u64)
                .read_to_end(&mut output);
            if read.is_err() || output.len() > output_limit {
                let _ = child.kill();
            }
            (writer.join(), read)
        });
        let status = child.wait()?;
        read_result?;
        write_result.map_err(|_| CryptoError::InputWorkerFailed)??;
        if output.len() > output_limit {
            return Err(CryptoError::AgeOutputTooLarge);
        }
        if !status.success() {
            return Err(CryptoError::AgeFailed(status.code()));
        }
        Ok(output)
    }
}

impl CryptoProvider for AgeCommandProvider {
    fn encrypt(&self, ssh_recipients: &[&str], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(CryptoError::SecretTooLarge);
        }
        if ssh_recipients.is_empty() {
            return Err(CryptoError::InvalidRecipient);
        }
        ssh_recipients
            .iter()
            .try_for_each(|recipient| validate_ssh_recipient(recipient))?;
        Ok(self
            .run(
                &encrypt_arguments(ssh_recipients),
                plaintext,
                MAX_CIPHERTEXT_SIZE,
            )?
            .to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if ciphertext.len() > MAX_CIPHERTEXT_SIZE {
            return Err(CryptoError::SecretTooLarge);
        }
        self.run(&self.decrypt_arguments(), ciphertext, MAX_PLAINTEXT_SIZE)
    }
}

impl AgeCommandProvider {
    fn decrypt_arguments(&self) -> Vec<OsString> {
        match &self.decryption {
            DecryptionMode::OnePassword => one_password_decrypt_arguments(),
            DecryptionMode::IdentityFile(path) => identity_decrypt_arguments(path),
        }
    }
}

fn encrypt_arguments(recipients: &[&str]) -> Vec<OsString> {
    let mut arguments = vec![OsString::from("--encrypt")];
    for recipient in recipients {
        arguments.push(OsString::from("--recipient"));
        arguments.push(OsString::from(recipient));
    }
    arguments
}

fn one_password_decrypt_arguments() -> Vec<OsString> {
    vec!["--decrypt".into(), "-j".into(), "1p".into()]
}

fn identity_decrypt_arguments(identity: &Path) -> Vec<OsString> {
    vec![
        "--decrypt".into(),
        "--identity".into(),
        identity.as_os_str().to_owned(),
    ]
}

fn validate_ssh_recipient(recipient: &str) -> Result<(), CryptoError> {
    let kind = recipient.split_ascii_whitespace().next();
    let has_control = recipient.chars().any(char::is_control);
    if !has_control && matches!(kind, Some("ssh-ed25519" | "ssh-rsa")) {
        Ok(())
    } else {
        Err(CryptoError::InvalidRecipient)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    fn strings(values: &[OsString]) -> Vec<&OsStr> {
        values.iter().map(OsString::as_os_str).collect()
    }

    #[test]
    fn encryption_argv_has_all_public_recipients() {
        let first = "ssh-ed25519 AAAAfirst operator";
        let second = "ssh-rsa AAAAsecond operator";
        assert_eq!(
            strings(&encrypt_arguments(&[first, second])),
            [
                OsStr::new("--encrypt"),
                OsStr::new("--recipient"),
                OsStr::new(first),
                OsStr::new("--recipient"),
                OsStr::new(second),
            ]
        );
    }

    #[test]
    fn decryption_uses_one_password_plugin() {
        assert_eq!(
            strings(&one_password_decrypt_arguments()),
            [OsStr::new("--decrypt"), OsStr::new("-j"), OsStr::new("1p")]
        );
    }

    #[test]
    fn identity_decryption_uses_runtime_path_as_one_argument() {
        let path = Path::new("/runtime/identity with spaces");
        assert_eq!(
            strings(&identity_decrypt_arguments(path)),
            [
                OsStr::new("--decrypt"),
                OsStr::new("--identity"),
                path.as_os_str(),
            ]
        );
    }

    #[test]
    fn only_ordinary_ssh_recipients_are_accepted() {
        assert!(validate_ssh_recipient("ssh-ed25519 AAAA").is_ok());
        assert!(validate_ssh_recipient("ssh-rsa AAAA comment").is_ok());
        assert!(validate_ssh_recipient("age1example").is_err());
        assert!(validate_ssh_recipient("ssh-ed25519 AAAA\nargument").is_err());
    }
}
