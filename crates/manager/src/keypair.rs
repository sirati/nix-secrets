//! Runs an operator leaf's keypair generator.
//!
//! Contract, for any program a consumer declares:
//!
//! - It runs as `nix run <installable> -- <args...>` on the operator's
//!   machine, only when the operator asks to generate. `args` come from the
//!   schema and carry no secret.
//! - Its stdin is empty (`/dev/null`).
//! - It writes the private key, exactly as it should be stored, to stdout.
//! - It writes the public key, exactly as it should be published, to file
//!   descriptor 3. It never writes either to disk.
//! - It exits 0. Stderr is shown on failure, bounded, and must not contain the
//!   private key.
//!
//! nix-secrets reads both pipes concurrently, rejects empty or oversized
//! output, encrypts the private key to the leaf's recipients, and stores the
//! public key in plain beside the ciphertext.

use command_fds::{CommandFdExt, FdMapping};
use nix_secrets_core::KeypairGenerator;
use std::ffi::OsString;
use std::io::Read;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub const PUBLIC_KEY_FD: i32 = 3;
pub const MAX_PRIVATE_KEY_BYTES: usize = 1024 * 1024;
pub const MAX_PUBLIC_KEY_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: u64 = 4096;

pub struct Keypair {
    pub private: Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
}

/// The argv that runs `generator`, starting with the program.
pub fn command_line(nix: &str, generator: &KeypairGenerator) -> Vec<OsString> {
    let mut argv = vec![
        OsString::from(nix),
        "--extra-experimental-features".into(),
        "nix-command flakes".into(),
        "run".into(),
        generator.installable.clone().into(),
        "--".into(),
    ];
    argv.extend(generator.args.iter().map(OsString::from));
    argv
}

/// Runs the generator through `nix`. Tests pass another program in `argv`.
pub fn generate(generator: &KeypairGenerator) -> Result<Keypair, String> {
    run(&command_line("nix", generator))
}

pub fn run(argv: &[OsString]) -> Result<Keypair, String> {
    let (program, arguments) = argv.split_first().ok_or("empty generator command")?;
    let (public_read, public_write) =
        std::io::pipe().map_err(|error| format!("cannot create a pipe: {error}"))?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
        .fd_mappings(vec![FdMapping {
            parent_fd: public_write.into(),
            child_fd: PUBLIC_KEY_FD,
        }])
        .map_err(|error| format!("cannot map the public key descriptor: {error}"))?;
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start the generator: {error}"))?;
    // The only write end left is the child's fd 3, so the reader sees EOF
    // when the child exits.
    drop(command);
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let mut public_read = public_read;
    let (private, public, diagnostics) = std::thread::scope(|scope| {
        let public = scope.spawn(move || bounded(&mut public_read, MAX_PUBLIC_KEY_BYTES));
        let diagnostics = scope.spawn(move || {
            let mut text = Vec::new();
            let _ = (&mut stderr).take(MAX_STDERR_BYTES).read_to_end(&mut text);
            let _ = std::io::copy(&mut stderr, &mut std::io::sink());
            String::from_utf8_lossy(&text).trim().to_owned()
        });
        let private = bounded(&mut stdout, MAX_PRIVATE_KEY_BYTES);
        (
            private,
            public.join().unwrap_or(Err("public key reader failed")),
            diagnostics.join().unwrap_or_default(),
        )
    });
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for the generator: {error}"))?;
    if !status.success() {
        return Err(if diagnostics.is_empty() {
            format!("generator failed with {status}")
        } else {
            format!("generator failed with {status}: {diagnostics}")
        });
    }
    let private =
        private.map_err(|problem| format!("generator private key on stdout {problem}"))?;
    let public = public.map_err(|problem| {
        format!("generator public key on descriptor {PUBLIC_KEY_FD} {problem}")
    })?;
    Ok(Keypair {
        private,
        public: public.to_vec(),
    })
}

fn bounded(reader: &mut impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut value = Zeroizing::new(Vec::new());
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut value)
        .map_err(|_| "could not be read")?;
    if value.is_empty() {
        Err("is empty")
    } else if value.len() > limit {
        Err("exceeds its size limit")
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(script: &str) -> Vec<OsString> {
        vec!["sh".into(), "-c".into(), script.into()]
    }

    #[test]
    fn reads_private_stdout_and_public_fd_3_exactly() {
        let pair = run(&shell(
            "printf 'PRIVATE\\0\\377' ; printf 'public-bytes\\n' >&3",
        ))
        .unwrap();
        assert_eq!(pair.private.as_slice(), b"PRIVATE\0\xff");
        assert_eq!(pair.public, b"public-bytes\n");
    }

    #[test]
    fn a_large_private_key_does_not_deadlock_the_public_pipe() {
        let pair = run(&shell(
            "head -c 300000 /dev/zero | tr '\\0' a; head -c 60000 /dev/zero | tr '\\0' b >&3",
        ))
        .unwrap();
        assert_eq!(pair.private.len(), 300_000);
        assert_eq!(pair.public.len(), 60_000);
    }

    #[test]
    fn missing_output_failure_and_limits_are_errors() {
        assert!(run(&shell("printf private"))
            .err()
            .unwrap()
            .contains("descriptor 3 is empty"));
        assert!(run(&shell("printf public >&3"))
            .err()
            .unwrap()
            .contains("stdout is empty"));
        let failed = run(&shell("echo broken >&2; exit 4")).err().unwrap();
        assert!(failed.contains("broken"), "{failed}");
        assert!(run(&shell("printf p; head -c 70000 /dev/zero >&3"))
            .err()
            .unwrap()
            .contains("size limit"));
    }

    #[test]
    fn nix_command_line_passes_schema_arguments_after_a_separator() {
        let generator = KeypairGenerator {
            installable: "github:owner/repo?dir=tool#signer".into(),
            args: vec!["keygen".into(), "--stdio".into()],
        };
        assert_eq!(
            command_line("nix", &generator),
            [
                "nix",
                "--extra-experimental-features",
                "nix-command flakes",
                "run",
                "github:owner/repo?dir=tool#signer",
                "--",
                "keygen",
                "--stdio"
            ]
            .map(OsString::from)
        );
    }
}
