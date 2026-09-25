use nix_secrets_core::Schema;
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::{
    async_ui::AsyncWriter, cli, client::BackendClient, command, controller::Controller, startup, ui,
};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
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
    progress("Connecting...")?;
    let repository = if invocation.is_local() {
        invocation.repository.clone()
    } else {
        remote_repository(&invocation.ssh_args, &invocation.repository)?
    };
    let remote_uid = if invocation.is_local() {
        None
    } else {
        Some(remote_uid(&invocation.ssh_args)?)
    };
    if remote_uid.is_some() {
        progress("Connected.")?;
    }
    let socket_directory = runtime_directory(&home).join("nix-secrets");
    fs::create_dir_all(&socket_directory)?;
    let socket_name = startup::socket_name(&repository);
    // Each remote frontend owns its SSH tunnel. Another terminal can then
    // remain connected when this one exits, while all tunnels still reach the
    // same backend socket on the repository host.
    let local_socket = if invocation.is_local() {
        socket_directory.join(&socket_name)
    } else {
        socket_directory.join(format!("frontend-{}-{socket_name}", std::process::id()))
    };
    let backend = if invocation.is_local() {
        command::backend(&repository, &local_socket)
    } else {
        let uid = remote_uid.expect("remote UID was resolved above");
        let remote_socket = PathBuf::from(format!("/run/user/{uid}/nix-secrets/{socket_name}"));
        command::remote_backend(
            &invocation.ssh_args,
            &repository,
            &local_socket,
            &remote_socket,
        )?
    };
    progress("Starting/Connecting backend...")?;
    let mut launcher = if invocation.is_local() {
        startup::ProcessLauncher::persistent()
    } else {
        startup::ProcessLauncher::ephemeral(&local_socket)
    };
    let connection = startup::connect_or_start(
        &local_socket,
        &backend,
        &mut launcher,
        Duration::from_secs(20),
    )?;
    if remote_uid.is_none() {
        progress("Connected.")?;
    }
    progress("Evaluating Nix...")?;
    let schema = evaluate(&invocation.ssh_args, &repository)?;
    let provider = one_password_scope(
        invocation
            .identity
            .map(AgeCommandProvider::identity_file)
            .unwrap_or_default(),
        invocation.shared_session,
    );
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
    let mut writer = AsyncWriter::spawn(controller, local_socket);
    ui::run(rows, &mut writer)?;
    Ok(())
}

fn progress(message: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{message}")?;
    stdout.flush()
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

/// Starts each 1Password decryption in its own session through the
/// `nix-secrets-1password` launcher installed next to this binary, so an
/// authorization covers one decryption and the prompt names nix-secrets.
fn one_password_scope(provider: AgeCommandProvider, shared: bool) -> AgeCommandProvider {
    if shared || !provider.uses_one_password() {
        return provider;
    }
    let launcher = env::current_exe()
        .ok()
        .and_then(|path| Some(path.parent()?.join("nix-secrets-1password")))
        .filter(|path| path.is_file());
    match launcher {
        Some(launcher) => provider.through(launcher, vec![]),
        None => provider,
    }
}
