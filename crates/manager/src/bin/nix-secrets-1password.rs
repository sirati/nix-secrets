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
//! once, then runs the program once per input and writes the outputs in the
//! same framing. A batch of secrets therefore raises exactly one prompt.
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
    while let Some(flag) =
        arguments.next_if(|argument| argument == "--shared-session" || argument == "--batch")
    {
        if flag == "--batch" {
            batch = true;
        } else {
            shared = true;
        }
    }
    let Some(program) = arguments.next() else {
        eprintln!(
            "usage: nix-secrets-1password [--shared-session] [--batch] PROGRAM [ARGUMENT...]"
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
    if let Err(message) = authorize() {
        eprintln!("nix-secrets-1password: {message}");
        return ExitCode::from(NOT_AUTHORIZED);
    }
    match inputs {
        Some(inputs) => run_batch(&program, &arguments, &inputs),
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

/// Reads `u32` big-endian length-prefixed inputs until end of file.
fn read_batch(input: &mut impl Read) -> Result<Vec<Vec<u8>>, String> {
    let mut inputs = Vec::new();
    loop {
        let mut length = [0; 4];
        match input.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(format!("cannot read the batch: {error}")),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_INPUT || inputs.len() == MAX_BATCH {
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
/// with that program's status; its stderr reaches ours unchanged.
fn run_batch(program: &OsStr, arguments: &[OsString], inputs: &[Vec<u8>]) -> ExitCode {
    let mut outputs = zeroize::Zeroizing::new(Vec::new());
    for input in inputs {
        let child = Command::new(program)
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                eprintln!(
                    "nix-secrets-1password: could not run {}: {error}",
                    program.to_string_lossy()
                );
                return ExitCode::from(127);
            }
        };
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let mut output = zeroize::Zeroizing::new(Vec::new());
        let read = std::thread::scope(|scope| {
            let writer = scope.spawn(move || stdin.write_all(input));
            let read = stdout.read_to_end(&mut output);
            let _ = writer.join();
            read
        });
        let status = match child.wait() {
            Ok(status) => status,
            Err(error) => {
                eprintln!("nix-secrets-1password: could not wait for the program: {error}");
                return ExitCode::FAILURE;
            }
        };
        if !status.success() {
            return exit_code(status);
        }
        if let Err(error) = read {
            eprintln!("nix-secrets-1password: could not read the program's output: {error}");
            return ExitCode::FAILURE;
        }
        let Ok(length) = u32::try_from(output.len()) else {
            eprintln!("nix-secrets-1password: an output is too large");
            return ExitCode::FAILURE;
        };
        outputs.extend_from_slice(&length.to_be_bytes());
        outputs.extend_from_slice(&output);
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
