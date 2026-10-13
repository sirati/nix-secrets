//! The detached process that signs SSH logins the operator approved.
//!
//! 1Password's SSH agent authorizes the process that asks, and for a
//! process without an app of its own it walks up to the nearest ancestor
//! with one. For the TUI that is the terminal, so an authorization would
//! cover every program in it. The TUI therefore never asks the agent for
//! a login signature itself. After the operator approves logins, it starts
//! `nix-secrets ssh-login-signer`, which starts a second copy in a new
//! session and exits. The second copy is reparented away from the TUI and
//! its terminal before it touches the agent. It asks the agent once right
//! away, so 1Password asks the operator before anything connects, and
//! then serves an agent socket that offers one key and signs only SSH
//! user authentication for one user with it. It exits when the TUI closes
//! its stdin, when the TUI exits, after [`LOGIN_GRANT_WINDOW`] or after
//! [`LOGIN_GRANT_SIGNATURES`] signatures.
use nix_secrets_core::git::agent::{read_message, write_message, FAILURE};
use nix_secrets_core::private_socket::PrivateSocket;
use nix_secrets_core::secret_request::is_same_or_descendant;
use nix_secrets_core::ssh_auth::{
    self, LoginGrantRequest, SignatureRequest, LOGIN_GRANT_SIGNATURES, LOGIN_GRANT_WINDOW,
};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// The subcommand of the `nix-secrets` binary that runs the signer.
pub const SUBCOMMAND: &str = "ssh-login-signer";
const DETACHED: &str = "--detached-from";

/// What the TUI tells the signer on its stdin.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// The client agent that holds the key, for example 1Password's.
    agent: PathBuf,
    login: LoginGrantRequest,
    /// Names this approval in the confirmation the agent signs.
    grant: String,
    /// The TUI. Only it and its descendants may use the signer's socket.
    owner: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
enum Ready {
    Ready { socket: PathBuf, pid: u32 },
    Failed { message: String },
}

static PROGRAM: OnceLock<PathBuf> = OnceLock::new();

/// Sets the `nix-secrets` binary that runs the signer. Without it the
/// running executable is used, which must then handle [`SUBCOMMAND`]
/// through [`main_if_invoked`].
pub fn set_program(program: PathBuf) {
    let _ = PROGRAM.set(program);
}

fn program() -> io::Result<PathBuf> {
    match PROGRAM.get() {
        Some(program) => Ok(program.clone()),
        None => std::env::current_exe(),
    }
}

/// A running signer. Dropping it closes the signer's stdin, and the signer
/// exits.
pub struct LoginSigner {
    socket: PathBuf,
    pid: u32,
    _stdin: ChildStdin,
}

impl LoginSigner {
    /// Starts a detached signer for `login` with the key in `agent` and
    /// waits until the agent signed its confirmation. With 1Password this
    /// waits for the operator to approve the signer there.
    pub fn spawn(agent: &Path, login: &LoginGrantRequest, grant: &str) -> Result<Self, String> {
        let program = program().map_err(|error| format!("cannot find the login signer: {error}"))?;
        let mut intermediate = Command::new(program)
            .arg(SUBCOMMAND)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("cannot start the login signer: {error}"))?;
        let mut stdin = intermediate.stdin.take().expect("piped stdin");
        let stdout = intermediate.stdout.take().expect("piped stdout");
        let config = Config {
            agent: agent.to_owned(),
            login: login.clone(),
            grant: grant.to_owned(),
            owner: std::process::id(),
        };
        let written = serde_json::to_writer(&mut stdin, &config)
            .map_err(io::Error::other)
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush());
        // The first copy only starts the detached one.
        let _ = intermediate.wait();
        written.map_err(|error| format!("cannot configure the login signer: {error}"))?;
        let mut line = String::new();
        BufReader::new(stdout.take(64 * 1024))
            .read_line(&mut line)
            .map_err(|error| format!("the login signer failed: {error}"))?;
        match serde_json::from_str::<Ready>(&line) {
            Ok(Ready::Ready { socket, pid }) => Ok(Self {
                socket,
                pid,
                _stdin: stdin,
            }),
            Ok(Ready::Failed { message }) => Err(message),
            Err(_) => Err("the login signer stopped before it was ready".into()),
        }
    }

    /// The signer's agent socket.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The detached signer's process.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Signs one SSH login challenge through the signer.
    pub fn sign(&self, request: &SignatureRequest) -> Result<Vec<u8>, String> {
        ssh_auth::sign(&self.socket, request)
    }
}

/// Runs the signer if the arguments ask for it; the binary then exits
/// with the returned code. Call it first thing in `main`.
pub fn main_if_invoked() -> Option<i32> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(SUBCOMMAND.as_ref()) {
        return None;
    }
    let detached_from = match (arguments.next(), arguments.next()) {
        (None, _) => None,
        (Some(flag), Some(pid)) if flag == DETACHED => pid.to_str().and_then(|pid| pid.parse().ok()),
        _ => return Some(2),
    };
    Some(match detached_from {
        None => detach(),
        Some(parent) => serve(parent),
    })
}

/// The first copy: starts the second and exits, so the second is
/// reparented away from the TUI. The second starts its own session.
fn detach() -> i32 {
    let Ok(program) = std::env::current_exe() else {
        return 1;
    };
    let mut command = Command::new(program);
    command
        .arg(SUBCOMMAND)
        .arg(DETACHED)
        .arg(std::process::id().to_string())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null());
    match command.spawn() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn reply(ready: &Ready) {
    let mut stdout = io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, ready);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

/// The second copy.
fn serve(parent: u32) -> i32 {
    match serve_inner(parent) {
        Ok(()) => 0,
        Err(message) => {
            reply(&Ready::Failed { message });
            1
        }
    }
}

fn serve_inner(parent: u32) -> Result<(), String> {
    // Away from the TUI's terminal and its signals.
    rustix::process::setsid().map_err(|error| format!("cannot start a session: {error}"))?;
    // Nothing touches the agent before the first copy is gone: the agent
    // must see this process with neither the TUI nor its terminal above it.
    let started = Instant::now();
    while rustix::process::getppid().map(|pid| pid.as_raw_nonzero().get() as u32) == Some(parent) {
        if started.elapsed() > Duration::from_secs(10) {
            return Err("the login signer could not detach from the TUI".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut stdin = BufReader::new(io::stdin());
    let mut line = String::new();
    stdin
        .by_ref()
        .take(64 * 1024)
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    let config: Config =
        serde_json::from_str(&line).map_err(|_| "malformed login signer configuration")?;
    config.login.validate()?;
    if is_same_or_descendant(std::process::id(), config.owner) {
        return Err("the login signer is still below the TUI".into());
    }
    let socket = PrivateSocket::bind(
        &nix_secrets_core::private_socket::runtime_directory(),
        "nix-secrets-login",
        "agent.sock",
    )
    .map_err(|error| format!("cannot create the login signer socket: {error}"))?;
    // 1Password asks the operator now, for this process.
    ssh_auth::confirm_login_grant(&config.agent, &config.login, &config.grant)
        .map_err(|error| format!("the SSH agent did not confirm the login approval: {error}"))?;
    reply(&Ready::Ready {
        socket: socket.path().to_owned(),
        pid: std::process::id(),
    });
    // The TUI closes stdin when the approval ends, or by exiting.
    let (closed, stdin_closed) = mpsc::channel();
    std::thread::spawn(move || {
        let mut rest = Vec::new();
        let _ = stdin.read_to_end(&mut rest);
        let _ = closed.send(());
    });
    let deadline = started + LOGIN_GRANT_WINDOW;
    let mut remaining = LOGIN_GRANT_SIGNATURES;
    while remaining > 0 && Instant::now() < deadline {
        if !matches!(stdin_closed.try_recv(), Err(mpsc::TryRecvError::Empty)) {
            break;
        }
        match socket.accept() {
            Ok(Some(stream)) => serve_connection(stream, &config, &mut remaining),
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => break,
        }
    }
    Ok(())
}

fn serve_connection(mut stream: UnixStream, config: &Config, remaining: &mut u32) {
    let allowed = rustix::net::sockopt::socket_peercred(&stream)
        .ok()
        .map(|peer| peer.pid.as_raw_nonzero().get() as u32)
        .is_some_and(|pid| is_same_or_descendant(pid, config.owner));
    if !allowed || stream.set_read_timeout(Some(Duration::from_secs(30))).is_err() {
        return;
    }
    while let Ok(Some(message)) = read_message(&mut stream) {
        let reply = answer(&message, config, remaining).unwrap_or_else(|| FAILURE[4..].to_vec());
        if write_message(&mut stream, &reply).is_err() {
            return;
        }
    }
}

/// Lists the one key, or signs one login for the approved user and key.
fn answer(message: &[u8], config: &Config, remaining: &mut u32) -> Option<Vec<u8>> {
    if message == [11] {
        return ssh_auth::identities(&config.login.public_key).ok();
    }
    if *remaining == 0 {
        return None;
    }
    let request = SignatureRequest {
        public_key: config.login.public_key.clone(),
        destination: config.login.destination.clone(),
        message: message.to_vec(),
    };
    request.validate().ok()?;
    *remaining -= 1;
    ssh_auth::sign(&config.agent, &request).ok()
}
