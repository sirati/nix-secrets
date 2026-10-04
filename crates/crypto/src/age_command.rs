use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use zeroize::Zeroizing;

use crate::{
    age_failure::CAPTURED_BYTES,
    secret::{MAX_CIPHERTEXT_SIZE, MAX_PLAINTEXT_SIZE},
    AgeFailure, CryptoError, CryptoProvider,
};

/// Encrypts and decrypts whole secrets with age through anonymous pipes.
#[derive(Clone)]
pub struct AgeCommandProvider {
    program: OsString,
    /// Launcher and leading arguments that run `program`, e.g. a session leader.
    launcher: Option<(PathBuf, Vec<OsString>)>,
    decryption: DecryptionMode,
    op_program: OsString,
    progress: Option<std::sync::Arc<dyn Fn(usize, usize, bool) + Send + Sync>>,
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
            progress: None,
            launcher: None,
        }
    }
}

impl AgeCommandProvider {
    pub fn set_progress(&mut self, callback: impl Fn(usize, usize, bool) + Send + Sync + 'static) {
        self.progress = Some(std::sync::Arc::new(callback));
    }
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            decryption: DecryptionMode::OnePassword,
            op_program: OsString::from("op"),
            progress: None,
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
            progress: None,
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
                let mut line = Vec::new();
                let mut last = (0, 0);
                let mut chunk = [0_u8; 1024];
                loop {
                    let count = match stderr.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    for byte in &chunk[..count] {
                        if captured.len() < CAPTURED_BYTES as usize {
                            captured.push(*byte);
                        }
                        if *byte == b'\n' {
                            if let (Some(callback), Some((done, total, waiting))) =
                                (&self.progress, parse_progress(&line))
                            {
                                if last.1 != total {
                                    last = (0, total);
                                }
                                last.0 = last.0.max(done);
                                callback(last.0, total, waiting);
                            }
                            line.clear();
                        } else if line.len() < 128 {
                            line.push(*byte);
                        }
                    }
                }
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
        if ciphertexts.is_empty() {
            return Ok(Vec::new());
        }
        let Some((launcher, prefix)) = &self.launcher else {
            if !self.uses_one_password() {
                let workers = std::thread::available_parallelism().map_or(1, usize::from);
                let done = std::sync::Mutex::new(0_usize);
                if let Some(callback) = &self.progress {
                    callback(0, ciphertexts.len(), false);
                }
                return ordered_parallel(ciphertexts, workers, |ciphertext| {
                    let value = self.decrypt(ciphertext)?;
                    let mut count = done.lock().expect("progress counter poisoned");
                    *count += 1;
                    if let Some(callback) = &self.progress {
                        callback(*count, ciphertexts.len(), false);
                    }
                    Ok(value)
                });
            }
            // A direct plugin provider has no shared authorization scope.
            // Keep this fallback serial; normal 1Password clients use the launcher.
            return ciphertexts
                .iter()
                .enumerate()
                .map(|(index, ciphertext)| {
                    if let Some(callback) = &self.progress {
                        callback(index, ciphertexts.len(), true);
                    }
                    let value = self.decrypt(ciphertext)?;
                    if let Some(callback) = &self.progress {
                        callback(index + 1, ciphertexts.len(), false);
                    }
                    Ok(value)
                })
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

/// Join the entire bounded wave before reporting its first input-order error.
/// Successful plaintext buffers drop and zeroize if any input fails; later
/// waves are never started and no partial batch is returned.
fn ordered_parallel<T: Sync, R: Send, E: Send>(
    inputs: &[T],
    workers: usize,
    run: impl Fn(&T) -> Result<R, E> + Sync,
) -> Result<Vec<R>, E> {
    let mut output = Vec::with_capacity(inputs.len());
    for wave in inputs.chunks(workers.max(1)) {
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = wave
                .iter()
                .map(|input| scope.spawn(|| run(input)))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("decrypt worker panicked"))
                .collect::<Vec<_>>()
        });
        for result in results {
            output.push(result?);
        }
    }
    Ok(output)
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

#[cfg(test)]
mod parallel_identity_tests {
    use super::ordered_parallel;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };
    #[test]
    fn bounded_identity_workers_overlap_keep_order_and_join_on_failure() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let finished = AtomicUsize::new(0);
        let barrier = Barrier::new(2);
        let result: Result<Vec<usize>, usize> = ordered_parallel(&[0, 1, 2, 3], 2, |value| {
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            barrier.wait();
            active.fetch_sub(1, Ordering::SeqCst);
            finished.fetch_add(1, Ordering::SeqCst);
            Ok(*value)
        });
        assert_eq!(result.unwrap(), [0, 1, 2, 3]);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(finished.load(Ordering::SeqCst), 4);
        finished.store(0, Ordering::SeqCst);
        let result: Result<Vec<usize>, usize> = ordered_parallel(&[0, 1, 2, 3], 2, |value| {
            barrier.wait();
            finished.fetch_add(1, Ordering::SeqCst);
            Err(*value)
        });
        assert_eq!(result, Err(0));
        assert_eq!(finished.load(Ordering::SeqCst), 2);
    }
}

// Only fixed public progress records are interpreted; child diagnostics are never labels.
fn parse_progress(line: &[u8]) -> Option<(usize, usize, bool)> {
    let text = std::str::from_utf8(line)
        .ok()?
        .strip_prefix("NIX_SECRETS_PROGRESS ")?;
    let parts: Vec<_> = text.split(' ').collect();
    if parts.len() != 3 {
        return None;
    }
    let done = parts[0].parse::<usize>().ok()?;
    let total = parts[1].parse::<usize>().ok()?;
    if total == 0 || total > 4096 || done > total {
        return None;
    }
    Some((
        done,
        total,
        match parts[2] {
            "one-password" => true,
            "decrypting" => false,
            _ => return None,
        },
    ))
}

#[cfg(test)]
mod progress_tests {
    use super::parse_progress;
    #[test]
    fn public_progress_parser_rejects_diagnostics_and_invalid_counts() {
        assert_eq!(
            parse_progress(b"NIX_SECRETS_PROGRESS 0 17 one-password"),
            Some((0, 17, true))
        );
        assert_eq!(
            parse_progress(b"NIX_SECRETS_PROGRESS 3 17 decrypting"),
            Some((3, 17, false))
        );
        for value in [
            b"secret diagnostic".as_slice(),
            b"NIX_SECRETS_PROGRESS 18 17 decrypting",
            b"NIX_SECRETS_PROGRESS 1 5000 decrypting",
            b"NIX_SECRETS_PROGRESS 1 2 private-label",
            b"NIX_SECRETS_PROGRESS 0 0 decrypting",
        ] {
            assert_eq!(parse_progress(value), None);
        }
    }
}

#[cfg(test)]
mod live_progress_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };

    #[test]
    #[ignore = "subprocess fixture invoked by live_stderr_progress_arrives_before_completion"]
    fn progress_child() {
        eprintln!("NIX_SECRETS_PROGRESS 0 3 one-password");
        std::thread::sleep(std::time::Duration::from_millis(300));
        eprintln!("NIX_SECRETS_PROGRESS 2 3 decrypting");
        eprintln!("NIX_SECRETS_PROGRESS 1 3 decrypting");
    }

    #[test]
    fn live_stderr_progress_arrives_before_completion() {
        let (send, receive) = mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_worker = finished.clone();
        let mut provider = AgeCommandProvider::new(std::env::current_exe().unwrap());
        provider.set_progress(move |done, total, waiting| {
            send.send((done, total, waiting)).unwrap();
        });
        let worker = std::thread::spawn(move || {
            let result = provider.run(
                &[
                    "--exact".into(),
                    "age_command::live_progress_tests::progress_child".into(),
                    "--ignored".into(),
                    "--nocapture".into(),
                ],
                &[],
                4096,
            );
            finished_worker.store(true, Ordering::SeqCst);
            result
        });
        assert_eq!(
            receive
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            (0, 3, true)
        );
        assert!(
            !finished.load(Ordering::SeqCst),
            "progress must stream while approval/child is pending"
        );
        assert_eq!(
            receive
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            (2, 3, false)
        );
        assert_eq!(
            receive
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            (2, 3, false),
            "progress never goes backwards"
        );
        worker.join().unwrap().unwrap();
    }
}
