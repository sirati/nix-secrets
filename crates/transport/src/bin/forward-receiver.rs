#![forbid(unsafe_code)]

use nix_secrets_transport::{login_shell_arguments, run_receiver};
use std::ffi::OsString;
use std::io;

fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let original = std::env::var_os("SSH_ORIGINAL_COMMAND");
    let arguments = match login_shell_arguments(arguments, original.as_ref()) {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("nix-secrets-forward-receiver: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = run_receiver(arguments, io::stdin().lock(), io::stdout()) {
        eprintln!("nix-secrets-forward-receiver: {error}");
        std::process::exit(1);
    }
}
