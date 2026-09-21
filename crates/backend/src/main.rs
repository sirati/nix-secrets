use nix_secrets_backend::{Arguments, run};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let result = Arguments::parse(env::args_os().skip(1))
        .map_err(|error| error.to_string())
        .and_then(|arguments| run(arguments).map_err(|error| error.to_string()));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nix-secrets-backend: {error}");
            ExitCode::FAILURE
        }
    }
}
