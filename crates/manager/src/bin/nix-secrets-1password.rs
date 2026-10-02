//! Runs one age decryption with exactly one 1Password authorization.
//!
//! age-plugin-1p starts `op item list | op item get -` as two concurrent
//! processes. In a session that 1Password has not authorized yet, each of them
//! raises its own prompt; rejecting one leaves the other to fail even when it
//! is approved. This launcher therefore authorizes first with a single `op`
//! call and only then runs age, whose `op` calls reuse that authorization.
//!
//! By default it also leads a new session without a controlling terminal.
//! The 1Password app binds such an authorization to the session leader and
//! names that executable in its prompt, so one approval covers exactly this
//! run and the prompt reads "nix-secrets-1password". `--shared-session`
//! keeps the caller's terminal session and its 10-minute authorization.
//!
//! `--batch` reads length-prefixed inputs (u32 big-endian) from stdin, asks
//! once, then runs at most one decrypt worker per available CPU and writes outputs in the
//! same framing. A batch of secrets therefore raises exactly one prompt.
//!
//! `--one-key` (with `--batch`) reads only the one SSH key that decrypts
//! every input, by its item reference, and passes it to each run as
//! `--identity /dev/fd/3`; see the `one_key` module.
#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitCode, ExitStatus, Stdio};

/// Exit status when 1Password did not authorize; age itself never uses it.
const NOT_AUTHORIZED: u8 = 77;
const MESSAGE_BYTES: u64 = 4096;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1).peekable();
    let mut shared = false;
    let mut batch = false;
    let mut one_key = false;
    while let Some(flag) = arguments.next_if(|argument| {
        argument == "--shared-session" || argument == "--batch" || argument == "--one-key"
    }) {
        if flag == "--batch" {
            batch = true;
        } else if flag == "--one-key" {
            one_key = true;
        } else {
            shared = true;
        }
    }
    if one_key && !batch {
        eprintln!("nix-secrets-1password: --one-key needs --batch");
        return ExitCode::from(2);
    }
    let Some(program) = arguments.next() else {
        eprintln!(
            "usage: nix-secrets-1password [--shared-session] [--batch [--one-key]] PROGRAM [ARGUMENT...]"
        );
        return ExitCode::from(2);
    };
    let arguments = arguments.collect::<Vec<_>>();
    // Read the whole batch before asking, so a malformed input never prompts.
    let inputs = if batch {
        match read_batch(&mut std::io::stdin().lock()) {
            Ok(inputs) => Some(inputs),
            Err(message) => {
                eprintln!("nix-secrets-1password: {message}");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };
    if !shared {
        if let Err(error) = rustix::process::setsid() {
            eprintln!("nix-secrets-1password: could not start a new session: {error}");
            return ExitCode::from(125);
        }
    }
    if one_key {
        let inputs = inputs.expect("--one-key needs --batch");
        let key = match one_key::list().and_then(|items| {
            let item = one_key::choose(&items, &inputs)?;
            one_key::read(item)
        }) {
            Ok(key) => key,
            Err(message) => {
                eprintln!("nix-secrets-1password: {message}");
                return ExitCode::from(NOT_AUTHORIZED);
            }
        };
        return run_batch(&program, &arguments, &inputs, Some(&key));
    }
    if let Err(message) = authorize() {
        eprintln!("nix-secrets-1password: {message}");
        return ExitCode::from(NOT_AUTHORIZED);
    }
    match inputs {
        Some(inputs) => run_batch(&program, &arguments, &inputs, None),
        None => match Command::new(&program).args(&arguments).status() {
            Ok(status) => exit_code(status),
            Err(error) => {
                eprintln!(
                    "nix-secrets-1password: could not run {}: {error}",
                    program.to_string_lossy()
                );
                ExitCode::from(127)
            }
        },
    }
}

/// Most inputs one batch may carry.
const MAX_BATCH: usize = 256;
/// Largest single input (the ciphertext bound of nix-secrets-crypto).
const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_BATCH_BYTES: usize = 256 * 1024 * 1024;

/// Reads `u32` big-endian length-prefixed inputs until end of file.
fn read_batch(input: &mut impl Read) -> Result<Vec<Vec<u8>>, String> {
    let mut inputs = Vec::new();
    let mut total = 0_usize;
    loop {
        let mut length = [0; 4];
        match input.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(format!("cannot read the batch: {error}")),
        }
        let length = u32::from_be_bytes(length) as usize;
        total = total.saturating_add(length);
        if length > MAX_INPUT || inputs.len() == MAX_BATCH || total > MAX_BATCH_BYTES {
            return Err("the batch is too large".into());
        }
        let mut body = vec![0; length];
        input
            .read_exact(&mut body)
            .map_err(|error| format!("cannot read the batch: {error}"))?;
        inputs.push(body);
    }
    if inputs.is_empty() {
        return Err("the batch is empty".into());
    }
    Ok(inputs)
}

/// Runs the program once per input under the one authorization and writes
/// each output length-prefixed to stdout. The first failure ends the batch
/// with the earliest failing input's status; stderr reaches ours unchanged.
/// With `key`, each run gets it as `--identity /dev/fd/3`, on a pipe the
/// launcher fills; it is never written to disk or passed as an argument.
fn run_batch(
    program: &OsStr,
    arguments: &[OsString],
    inputs: &[Vec<u8>],
    key: Option<&[u8]>,
) -> ExitCode {
    // Keep 1Password authorization and the selected key local; only decrypt
    // subprocesses run concurrently, at most one per available CPU.
    let workers = std::thread::available_parallelism().map_or(1, usize::from);
    let mut outputs = zeroize::Zeroizing::new(Vec::new());
    for wave in inputs.chunks(workers) {
        let values = match ordered_parallel(wave, workers, |input| {
            run_input(program, arguments, input, key)
        }) {
            Ok(values) => values,
            Err(status) => return status,
        };
        for output in values {
            let Ok(length) = u32::try_from(output.len()) else {
                return ExitCode::FAILURE;
            };
            if outputs.len().saturating_add(output.len()).saturating_add(4) > MAX_BATCH_BYTES {
                eprintln!("nix-secrets-1password: the output batch is too large");
                return ExitCode::FAILURE;
            }
            outputs.extend_from_slice(&length.to_be_bytes());
            outputs.extend_from_slice(&output);
        }
    }
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(&outputs).and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nix-secrets-1password: could not write the outputs: {error}");
            ExitCode::FAILURE
        }
    }
}

// Bound subprocesses and temporary buffers. Join in input order and reap all
// workers before returning; no partial plaintext batch is published on failure.
fn ordered_parallel<T: Sync, R: Send, E: Send>(
    inputs: &[T],
    workers: usize,
    run: impl Fn(&T) -> Result<R, E> + Sync,
) -> Result<Vec<R>, E> {
    let mut outputs = Vec::with_capacity(inputs.len());
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
            outputs.push(result?);
        }
    }
    Ok(outputs)
}
fn run_input(
    program: &OsStr,
    arguments: &[OsString],
    input: &[u8],
    key: Option<&[u8]>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ExitCode> {
    use command_fds::{CommandFdExt, FdMapping};
    let mut command = Command::new(program);
    command.args(arguments);
    let mut key_writer = None;
    if let Some(key) = key {
        let (read, write) = match std::io::pipe() {
            Ok(pipe) => pipe,
            Err(error) => {
                eprintln!("nix-secrets-1password: cannot create a pipe: {error}");
                return Err(ExitCode::FAILURE);
            }
        };
        command.args(["--identity", "/dev/fd/3"]);
        if let Err(error) = command.fd_mappings(vec![FdMapping {
            parent_fd: read.into(),
            child_fd: 3,
        }]) {
            eprintln!("nix-secrets-1password: cannot pass the key: {error}");
            return Err(ExitCode::FAILURE);
        }
        key_writer = Some((write, key));
    }
    let child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            eprintln!(
                "nix-secrets-1password: could not run {}: {error}",
                program.to_string_lossy()
            );
            return Err(ExitCode::from(127));
        }
    };
    // The parent's copy of the read end is closed with the command.
    drop(command);
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut output = zeroize::Zeroizing::new(Vec::new());
    let read = std::thread::scope(|scope| {
        if let Some((mut write, key)) = key_writer.take() {
            scope.spawn(move || {
                let _ = write.write_all(key);
            });
        }
        let writer = scope.spawn(move || stdin.write_all(input));
        let read = (&mut stdout)
            .take(nix_secrets_crypto::MAX_CIPHERTEXT_SIZE as u64 + 1)
            .read_to_end(&mut output);
        if output.len() > nix_secrets_crypto::MAX_CIPHERTEXT_SIZE {
            let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        }
        let _ = writer.join();
        read
    });
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("nix-secrets-1password: could not wait for the program: {error}");
            return Err(ExitCode::FAILURE);
        }
    };
    if !status.success() {
        return Err(exit_code(status));
    }
    if let Err(error) = read {
        eprintln!("nix-secrets-1password: could not read the program's output: {error}");
        return Err(ExitCode::FAILURE);
    }
    if output.len() > nix_secrets_crypto::MAX_CIPHERTEXT_SIZE {
        eprintln!("nix-secrets-1password: an output is too large");
        return Err(ExitCode::FAILURE);
    }
    Ok(output)
}

/// Asks 1Password once. `op vault list` needs an authorized session and
/// prints only vault names, which are discarded.
fn authorize() -> Result<(), String> {
    let mut child = Command::new("op")
        .args(["vault", "list", "--format=json"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("1Password CLI could not be started: op: {error}"))?;
    let mut message = Vec::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(MESSAGE_BYTES).read_to_end(&mut message);
    }
    let status = child
        .wait()
        .map_err(|error| format!("1Password CLI failed: {error}"))?;
    if status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&message);
    let message = message
        .lines()
        .map(|line| strip_log_prefix(line.trim()))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Err(format!("1Password authorization failed: {message}"))
}

/// op prefixes errors with `[ERROR] YYYY/MM/DD HH:MM:SS `.
fn strip_log_prefix(line: &str) -> &str {
    match line.strip_prefix("[ERROR] ") {
        Some(rest) if rest.len() > 20 => &rest[20..],
        _ => line,
    }
}

fn exit_code(status: ExitStatus) -> ExitCode {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitCode::from(code as u8),
        (None, Some(signal)) => ExitCode::from(128 + signal as u8),
        (None, None) => ExitCode::FAILURE,
    }
}

/// `--one-key`: which 1Password SSH key decrypts the whole batch, found from
/// item metadata, and that one private key, read by its item reference.
///
/// age-plugin-1p (`age -j 1p`) runs `op item list | op item get -` and so
/// reads the private key of every SSH key item in the account. Here only
/// `op item list` (metadata: names, vaults and fingerprints, no key
/// material) and one `op read` of the matching item run. The desktop app
/// still authorizes the account for this session: 1Password has no
/// narrower authorization for the CLI.
mod one_key {
    use super::*;

    /// An SSH key item: its `op://vault/item` reference and fingerprint.
    #[derive(Debug, Eq, PartialEq)]
    pub struct Item {
        pub vault: String,
        pub id: String,
        pub title: String,
        pub fingerprint: String,
    }

    /// Parses `op item list --categories "SSH Key" --format=json`.
    pub fn parse_items(json: &[u8]) -> Result<Vec<Item>, String> {
        let value: serde_json::Value = serde_json::from_slice(json)
            .map_err(|error| format!("1Password listed SSH keys in an unexpected form: {error}"))?;
        let items = value
            .as_array()
            .ok_or("1Password listed SSH keys in an unexpected form")?;
        Ok(items
            .iter()
            .filter_map(|item| {
                Some(Item {
                    vault: item["vault"]["id"].as_str()?.to_owned(),
                    id: item["id"].as_str()?.to_owned(),
                    title: item["title"].as_str().unwrap_or("").to_owned(),
                    fingerprint: item["additional_information"].as_str()?.to_owned(),
                })
            })
            .filter(|item| valid_reference_part(&item.vault) && valid_reference_part(&item.id))
            .collect())
    }

    fn valid_reference_part(value: &str) -> bool {
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }

    /// The one item every input can be decrypted with.
    pub fn choose<'a>(items: &'a [Item], inputs: &[Vec<u8>]) -> Result<&'a Item, String> {
        let stanzas = inputs
            .iter()
            .map(|input| {
                nix_secrets_crypto::ssh_stanza_tags(input)
                    .map(|tags| tags.into_iter().map(|(_, tag)| tag).collect::<Vec<_>>())
                    .map_err(|_| "an input is not an age file".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        items
            .iter()
            .find(|item| {
                nix_secrets_crypto::fingerprint_stanza_tag(&item.fingerprint)
                    .is_some_and(|tag| stanzas.iter().all(|tags| tags.contains(&tag)))
            })
            .ok_or_else(|| {
                "no SSH key in your 1Password account can decrypt every requested value; \
                 add the recipient key to 1Password"
                    .to_owned()
            })
    }

    /// Lists the SSH key items. The first `op` call of the run: it raises
    /// the one authorization prompt.
    pub fn list() -> Result<Vec<Item>, String> {
        let output = op(&["item", "list", "--categories", "SSH Key", "--format=json"])?;
        parse_items(&output)
    }

    /// Reads exactly one private key, by its vault and item IDs.
    pub fn read(item: &Item) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        let reference = format!("op://{}/{}/private key", item.vault, item.id);
        Ok(zeroize::Zeroizing::new(op(&["read", &reference])?))
    }

    fn op(arguments: &[&str]) -> Result<Vec<u8>, String> {
        let output = Command::new("op")
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("1Password CLI could not be started: op: {error}"))?;
        if output.status.success() {
            return Ok(output.stdout);
        }
        let message = String::from_utf8_lossy(&output.stderr);
        let message = message
            .lines()
            .map(|line| strip_log_prefix(line.trim()))
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        Err(format!("1Password authorization failed: {message}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn lists_only_well_formed_items() {
            let items = parse_items(br#"[
                {"id":"abc123","title":"IT Secrets","vault":{"id":"v1"},"additional_information":"SHA256:x"},
                {"id":"../x","title":"odd","vault":{"id":"v1"},"additional_information":"SHA256:y"},
                {"id":"def","title":"no fp","vault":{"id":"v1"}}
            ]"#).unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].title, "IT Secrets");
        }
    }
}

#[cfg(test)]
mod parallel_tests {
    use super::ordered_parallel;
    use std::sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn workers_overlap_are_bounded_and_results_keep_input_order() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let barrier = Barrier::new(2);
        let result: Result<Vec<_>, ()> = ordered_parallel(&[0, 1, 2, 3], 2, |input| {
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            barrier.wait();
            active.fetch_sub(1, Ordering::SeqCst);
            Ok(*input)
        });
        assert_eq!(result.unwrap(), [0, 1, 2, 3]);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn failure_reaps_wave_selects_first_input_error_and_stops_later_work() {
        let finished = AtomicUsize::new(0);
        let barrier = Barrier::new(2);
        let result: Result<Vec<usize>, usize> = ordered_parallel(&[0, 1, 2, 3], 2, |input| {
            barrier.wait();
            finished.fetch_add(1, Ordering::SeqCst);
            Err(*input)
        });
        assert_eq!(result, Err(0));
        assert_eq!(finished.load(Ordering::SeqCst), 2);
    }
}
