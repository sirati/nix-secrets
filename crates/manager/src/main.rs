use nix_secrets_core::Schema;
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::{
    cli, client::BackendClient, command, controller::Controller, startup, ui,
};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

fn main() {
    if let Err(error) = run() {
        eprintln!("nix-secrets: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set")?;
    let invocation = cli::parse(env::args_os().skip(1), &home)?;
    let repository = if invocation.is_local() {
        invocation.repository.clone()
    } else {
        remote_repository(&invocation.ssh_args, &invocation.repository)?
    };
    let schema = evaluate(&invocation.ssh_args, &repository)?;
    let socket_directory = runtime_directory(&home).join("nix-secrets");
    fs::create_dir_all(&socket_directory)?;
    let socket_name = socket_name(&repository);
    let local_socket = socket_directory.join(&socket_name);
    let backend = if invocation.is_local() {
        command::backend(&repository, &local_socket)
    } else {
        let uid = remote_uid(&invocation.ssh_args)?;
        let remote_socket = PathBuf::from(format!("/run/user/{uid}/nix-secrets/{socket_name}"));
        command::remote_backend(
            &invocation.ssh_args,
            &repository,
            &local_socket,
            &remote_socket,
        )?
    };
    let connection = startup::connect_or_start(
        &local_socket,
        &backend,
        &mut startup::ProcessLauncher,
        Duration::from_secs(20),
    )?;
    let provider = invocation
        .identity
        .map(AgeCommandProvider::identity_file)
        .unwrap_or_default();
    let known_hosts = vec![
        home.join(".ssh/known_hosts"),
        PathBuf::from("/etc/ssh/ssh_known_hosts"),
    ];
    let mut controller = Controller::new(
        BackendClient::new(connection.stream),
        schema,
        provider,
        known_hosts,
    )?;
    let rows = controller.rows()?;
    ui::run(rows, &mut controller)?;
    Ok(())
}

fn evaluate(
    ssh_arguments: &[OsString],
    repository: &Path,
) -> Result<Schema, Box<dyn std::error::Error>> {
    let evaluation = command::nix_eval(repository, "nixSecretsSchemas");
    let output = if ssh_arguments.is_empty() {
        evaluation.command().output()?
    } else {
        let remote = command::argv(&evaluation)
            .map(OsString::from)
            .collect::<Vec<_>>();
        command::ssh(ssh_arguments, &remote)?.command().output()?
    };
    require_success(output).and_then(|bytes| {
        let json = String::from_utf8(bytes)?;
        Ok(Schema::from_json(&json)?)
    })
}

fn remote_repository(
    arguments: &[OsString],
    repository: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let text = repository
        .to_str()
        .ok_or("remote repository path is not UTF-8")?;
    if text != "~" && !text.starts_with("~/") {
        return Ok(repository.to_owned());
    }
    let output = command::ssh(arguments, &["pwd".into(), "-P".into()])?
        .command()
        .output()?;
    let home = String::from_utf8(require_success(output)?)?;
    let home = Path::new(home.trim());
    if !home.is_absolute() {
        return Err("remote login directory is not absolute".into());
    }
    Ok(if text == "~" {
        home.to_owned()
    } else {
        home.join(&text[2..])
    })
}

fn remote_uid(arguments: &[OsString]) -> Result<u32, Box<dyn std::error::Error>> {
    let output = command::ssh(arguments, &["id".into(), "-u".into()])?
        .command()
        .output()?;
    let bytes = require_success(output)?;
    let value = String::from_utf8(bytes)?;
    Ok(value.trim().parse()?)
}

fn require_success(output: Output) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if output.status.success() {
        return Ok(output.stdout);
    }
    let message = String::from_utf8_lossy(&output.stderr);
    Err(format!("command failed: {}", message.trim()).into())
}

fn runtime_directory(home: &Path) -> PathBuf {
    env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/state"))
}

fn socket_name(repository: &Path) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    repository.hash(&mut hasher);
    format!("backend-{:016x}.sock", hasher.finish())
}
