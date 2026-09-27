use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use zeroize::Zeroizing;

use crate::{
    AgeFailure, CryptoError, CryptoProvider,
    age_failure::CAPTURED_BYTES,
    secret::{MAX_CIPHERTEXT_SIZE, MAX_PLAINTEXT_SIZE},
};

/// Encrypts and decrypts whole secrets with age through anonymous pipes.
#[derive(Clone)]
pub struct AgeCommandProvider {
    program: OsString,
    /// Launcher and leading arguments that run `program`, e.g. a session leader.
    launcher: Option<(PathBuf, Vec<OsString>)>,
    decryption: DecryptionMode,
    op_program: OsString,
}

#[derive(Clone)]
enum DecryptionMode {
    OnePassword,
    IdentityFile(PathBuf),
}

impl Default for AgeCommandProvider {
    fn default() -> Self {
        Self {
            program: OsString::from("age"),
            decryption: DecryptionMode::OnePassword,
            op_program: OsString::from("op"),
            launcher: None,
        }
    }
}

impl AgeCommandProvider {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            decryption: DecryptionMode::OnePassword,
            op_program: OsString::from("op"),
            launcher: None,
        }
    }

    /// Uses an SSH private key supplied only at runtime to decrypt secrets.
    pub fn identity_file(identity: impl Into<PathBuf>) -> Self {
        Self::with_identity_file("age", identity)
    }

    /// Where the private key for decryption comes from, for display.
    pub fn identity_description(&self) -> String {
        match &self.decryption {
            DecryptionMode::OnePassword => {
                "1Password on this machine (age-plugin-1p), one authorization".into()
            }
            DecryptionMode::IdentityFile(path) => format!("identity file {}", path.display()),
        }
    }

    /// Whether decryption asks 1Password for the private key.
    pub fn uses_one_password(&self) -> bool {
        matches!(self.decryption, DecryptionMode::OnePassword)
    }

    /// Names the 1Password CLI that is probed to explain a failed plugin run.
    pub fn with_one_password_cli(mut self, program: impl Into<OsString>) -> Self {
        self.op_program = program.into();
        self
    }

    /// Runs decryption through `launcher prefix... <age> <arguments...>`. The
    /// manager uses this to start age in its own session without a controlling
    /// terminal, so 1Password scopes an authorization to that one run.
    pub fn through(mut self, launcher: impl Into<PathBuf>, prefix: Vec<OsString>) -> Self {
        self.launcher = Some((launcher.into(), prefix));
        self
    }

    /// Selects both the age executable and a runtime SSH identity file.
    pub fn with_identity_file(program: impl Into<OsString>, identity: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            decryption: DecryptionMode::IdentityFile(identity.into()),
            op_program: OsString::from("op"),
            launcher: None,
        }
    }

    fn run(
        &self,
        arguments: &[OsString],
        input: &[u8],
        output_limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        // Encryption uses only public SSH recipients and never contacts 1Password.
        self.run_with(None, arguments, input, output_limit)
    }

    fn run_with(
        &self,
        launcher: Option<&(PathBuf, Vec<OsString>)>,
        arguments: &[OsString],
        input: &[u8],
        output_limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        // AGEDEBUG=plugin would copy plugin traffic, including unwrapped file
        // keys, to stderr, which is captured for error reports.
        let mut command = match launcher {
            Some((launcher, prefix)) => {
                let mut command = Command::new(launcher);
                command.args(prefix).arg(&self.program);
                command
            }
            None => Command::new(&self.program),
        };
        let mut child = command
            .args(arguments)
            .env_remove("AGEDEBUG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            CryptoError::AgeIo(std::io::Error::other("age stdin was not created"))
        })?;
        let mut stdout = child.stdout.take().ok_or_else(|| {
            CryptoError::AgeIo(std::io::Error::other("age stdout was not created"))
        })?;
        let mut stderr = child.stderr.take().ok_or_else(|| {
            CryptoError::AgeIo(std::io::Error::other("age stderr was not created"))
        })?;
        let input = Zeroizing::new(input.to_vec());
        let mut output = Zeroizing::new(Vec::with_capacity(output_limit.min(4096)));
        let (write_result, read_result, diagnostics) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || stdin.write_all(&input));
            let diagnostics = scope.spawn(move || {
                let mut captured = Vec::new();
                let _ = stderr
                    .by_ref()
                    .take(CAPTURED_BYTES)
                    .read_to_end(&mut captured);
                let _ = std::io::copy(&mut stderr, &mut std::io::sink());
                captured
            });
            let read = stdout
                .by_ref()
                .take((output_limit + 1) as u64)
                .read_to_end(&mut output);
            if read.is_err() || output.len() > output_limit {
                let _ = child.kill();
            }
            (writer.join(), read, diagnostics.join())
        });
        let status = child.wait()?;
        read_result?;
        if output.len() > output_limit {
            return Err(CryptoError::AgeOutputTooLarge);
        }
        if !status.success() {
            let mut failure = AgeFailure::new(status, &diagnostics.unwrap_or_default());
            failure.probe_one_password(&self.op_program);
            return Err(CryptoError::AgeFailed(Box::new(failure)));
        }
        write_result.map_err(|_| CryptoError::InputWorkerFailed)??;
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
        if self.launcher.is_some() && self.uses_one_password() {
            // The one-key path of the launcher reads only the matching key.
            return self
                .decrypt_batch(&[ciphertext])?
                .pop()
                .ok_or(CryptoError::AgeIo(std::io::Error::other("no output")));
        }
        self.run_with(
            self.launcher.as_ref(),
            &self.decrypt_arguments(),
            ciphertext,
            MAX_PLAINTEXT_SIZE,
        )
    }

    /// Decrypts several ciphertexts. With a launcher, all of them run inside
    /// one launcher invocation (`--batch`), so 1Password authorizes once for
    /// the whole batch; age still runs once per ciphertext.
    fn decrypt_batch(&self, ciphertexts: &[&[u8]]) -> Result<Vec<Zeroizing<Vec<u8>>>, CryptoError> {
        if ciphertexts
            .iter()
            .any(|ciphertext| ciphertext.len() > MAX_CIPHERTEXT_SIZE)
        {
            return Err(CryptoError::SecretTooLarge);
        }
        let Some((launcher, prefix)) = &self.launcher else {
            return ciphertexts
                .iter()
                .map(|ciphertext| self.decrypt(ciphertext))
                .collect();
        };
        if ciphertexts.is_empty() {
            return Ok(Vec::new());
        }
        let mut input = Vec::new();
        for ciphertext in ciphertexts {
            input.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
            input.extend_from_slice(ciphertext);
        }
        let mut batch_prefix = prefix.clone();
        batch_prefix.push("--batch".into());
        // With 1Password the launcher reads exactly the one key that
        // decrypts the batch and hands it to age; age-plugin-1p would read
        // every SSH key in the account.
        let arguments = if self.uses_one_password() {
            batch_prefix.push("--one-key".into());
            vec![OsString::from("--decrypt")]
        } else {
            self.decrypt_arguments()
        };
        let output = self.run_with(
            Some(&(launcher.clone(), batch_prefix)),
            &arguments,
            &input,
            ciphertexts.len() * (MAX_PLAINTEXT_SIZE + 4),
        )?;
        let mut rest = output.as_slice();
        let mut plaintexts = Vec::with_capacity(ciphertexts.len());
        while !rest.is_empty() {
            let malformed = || CryptoError::AgeIo(std::io::Error::other("malformed batch output"));
            let length =
                u32::from_be_bytes(rest.get(..4).ok_or_else(malformed)?.try_into().unwrap())
                    as usize;
            let value = rest.get(4..4 + length).ok_or_else(malformed)?;
            plaintexts.push(Zeroizing::new(value.to_vec()));
            rest = &rest[4 + length..];
        }
        if plaintexts.len() != ciphertexts.len() {
            return Err(CryptoError::AgeIo(std::io::Error::other(
                "the launcher returned a different number of values",
            )));
        }
        Ok(plaintexts)
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
