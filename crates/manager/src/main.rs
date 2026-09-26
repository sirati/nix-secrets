use nix_secrets_core::Schema;
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::{
    async_ui::AsyncWriter, cli, client::BackendClient, command, controller::Controller, startup,
    ui, with_secrets,
};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

fn main() {
    let mut arguments = env::args_os().skip(1).peekable();
    let result = if arguments
        .next_if(|argument| argument == "pipe-secret")
        .is_some()
    {
        pipe_secret(arguments.collect())
    } else if arguments
        .next_if(|argument| argument == "with-secrets")
        .is_some()
    {
        with_secrets(arguments.collect())
    } else {
        run(arguments.collect()).map(|()| 0)
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("nix-secrets: {error}");
            std::process::exit(1);
        }
    }
}

/// Hands one value to a command's stdin, or to a non-terminal stdout.
/// Nothing except the value is written to stdout.
fn pipe_secret(arguments: Vec<OsString>) -> Result<i32, Box<dyn std::error::Error>> {
    use nix_secrets_core::secret_request::SESSION_ENVIRONMENT;
    use nix_secrets_manager::pipe_secret::{deliver, parse, Sink};
    use std::io::IsTerminal;
    let invocation = parse(arguments, env::current_dir()?)?;
    let identifier = &invocation.identifier;
    let value = match env::var_os(SESSION_ENVIRONMENT).filter(|value| !value.is_empty()) {
        // Inside `with-secrets`: only the approved batch, never a new prompt.
        Some(session) if !invocation.options.local => {
            nix_secrets_core::secret_session::fetch(Path::new(&session), identifier)
                .map_err(|error| format!("{identifier}: {error}"))?
        }
        _ if invocation.options.local => {
            let mut values =
                decrypt_locally(&invocation.options, std::slice::from_ref(identifier))?;
            values
                .remove(identifier)
                .ok_or("the value was not decrypted")?
        }
        _ => {
            let home = home()?;
            let stream =
                with_secrets::connect_backend(&invocation.options, &runtime_directory(&home))?;
            let session = with_secrets::request(stream, std::slice::from_ref(identifier))?;
            let value = nix_secrets_core::secret_session::fetch(&session.socket, identifier);
            session.end()?;
            value.map_err(|error| format!("{identifier}: {error}"))?
        }
    };
    let status = match &invocation.command {
        Some(command) => deliver(&value, Sink::Command(command))?,
        None => {
            let stdout = io::stdout();
            let is_terminal = stdout.is_terminal();
            deliver(
                &value,
                Sink::Stdout {
                    output: &mut stdout.lock(),
                    is_terminal,
                },
            )?
        }
    };
    Ok(status.map_or(0, exit_code))
}

/// Asks the TUI for a batch of values (or decrypts them with `--local`),
/// runs the command with `NIX_SECRETS_SESSION`, and ends the session when
/// it exits. Returns the command's status.
fn with_secrets(arguments: Vec<OsString>) -> Result<i32, Box<dyn std::error::Error>> {
    use nix_secrets_core::secret_request::SESSION_ENVIRONMENT;
    let invocation = with_secrets::parse(arguments, env::current_dir()?)?;
    let (program, arguments) = invocation
        .command
        .split_first()
        .expect("parse requires a command");
    let mut command = std::process::Command::new(program);
    command.args(arguments);
    if invocation.options.local {
        let values = decrypt_locally(&invocation.options, &invocation.identifiers)?;
        let session = nix_secrets_core::secret_session::SecretSession::bind(
            &nix_secrets_core::private_socket::runtime_directory(),
            values,
            std::process::id(),
        )?;
        let mut child = command
            .env(SESSION_ENVIRONMENT, session.path())
            .spawn()
            .map_err(|error| format!("cannot start {program:?}: {error}"))?;
        let mut status = None;
        session.serve_until(|| {
            status = child.try_wait().ok().flatten();
            status.is_some()
        })?;
        drop(session);
        return Ok(exit_code(status.expect("served until the command exited")));
    }
    let home = home()?;
    let stream = with_secrets::connect_backend(&invocation.options, &runtime_directory(&home))?;
    let session = with_secrets::request(stream, &invocation.identifiers)?;
    let status = command.env(SESSION_ENVIRONMENT, &session.socket).status();
    let ended = session.end();
    let status = status.map_err(|error| format!("cannot run {program:?}: {error}"))?;
    ended?;
    Ok(exit_code(status))
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

fn home() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set")?)
}

/// `--local`: decrypts the values in this process with one provider batch,
/// so 1Password asks once.
fn decrypt_locally(
    options: &with_secrets::Options,
    identifiers: &[String],
) -> Result<nix_secrets_manager::secret_values::Values, Box<dyn std::error::Error>> {
    let home = home()?;
    let (stream, schema) = match (&options.backend_socket, &options.schema_file) {
        (Some(socket), Some(schema)) => (
            nix_secrets_manager::socket::connect_verified(socket)?,
            Schema::from_json(&fs::read_to_string(schema)?)?,
        ),
        _ => {
            let repository = fs::canonicalize(&options.repository)?;
            let socket_directory = runtime_directory(&home).join("nix-secrets");
            fs::create_dir_all(&socket_directory)?;
            let socket = socket_directory.join(startup::socket_name(&repository));
            let connection = startup::connect_or_start(
                &socket,
                &command::backend(&repository, &socket),
                &mut startup::ProcessLauncher::persistent(),
                Duration::from_secs(20),
            )?;
            // A persistent backend outlives this command, like the TUI's.
            (connection.stream, evaluate(&[], &repository)?)
        }
    };
    let provider = one_password_scope(
        options
            .identity
            .clone()
            .map(AgeCommandProvider::identity_file)
            .unwrap_or_default(),
        options.shared_session,
    );
    let mut client = BackendClient::new(stream);
    let batch = nix_secrets_manager::secret_values::load(&mut client, &schema, identifiers)?;
    Ok(batch.decrypt(&provider)?)
}

fn run(arguments: Vec<OsString>) -> Result<(), Box<dyn std::error::Error>> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set")?;
    let invocation = cli::parse(arguments, &home)?;
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

/// Runs each 1Password decryption through the `nix-secrets-1password`
/// launcher installed next to this binary. It authorizes once before age
/// starts, so a decryption raises at most one prompt, and by default gives
/// each decryption its own session so one approval covers one decryption.
fn one_password_scope(provider: AgeCommandProvider, shared: bool) -> AgeCommandProvider {
    if !provider.uses_one_password() {
        return provider;
    }
    let launcher = env::current_exe()
        .ok()
        .and_then(|path| Some(path.parent()?.join("nix-secrets-1password")))
        .filter(|path| path.is_file());
    match launcher {
        Some(launcher) => {
            let prefix = if shared {
                vec!["--shared-session".into()]
            } else {
                vec![]
            };
            provider.through(launcher, prefix)
        }
        None => provider,
    }
}
