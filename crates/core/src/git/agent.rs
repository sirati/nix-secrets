//! A private ssh-agent socket that relays a commit's signing requests to the
//! frontend's agent.
//!
//! Only two requests pass: listing identities, and signing an SSHSIG blob in
//! the `git` namespace, which is what `ssh-keygen -Y sign` sends for a git
//! commit. Adding, removing, locking, extensions and signing anything else,
//! such as an SSH login challenge, are refused with `SSH_AGENT_FAILURE`.
//! The frontend applies the same filter before it touches its agent, so a
//! compromised backend host cannot use the relay for anything else either.
use rustix::net::sockopt::socket_peercred;
use rustix::process::geteuid;
use std::fs::{self, DirBuilder};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

const REQUEST_IDENTITIES: u8 = 11;
const SIGN_REQUEST: u8 = 13;
/// `SSH_AGENT_FAILURE` as a framed reply.
pub const FAILURE: [u8; 5] = [0, 0, 0, 1, 5];
/// Agent messages are small; this bounds what either side reads.
pub const MAX_MESSAGE: usize = 256 * 1024;
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// Whether an agent request (the body, without its length) may be relayed.
pub fn permitted(message: &[u8]) -> Result<(), String> {
    match message.first() {
        Some(&REQUEST_IDENTITIES) if message.len() == 1 => Ok(()),
        Some(&SIGN_REQUEST) => {
            let mut rest = &message[1..];
            let _key = take_string(&mut rest)?;
            let data = take_string(&mut rest)?;
            if rest.len() != 4 {
                return Err("malformed sign request".into());
            }
            let mut data = data
                .strip_prefix(SSHSIG_MAGIC)
                .ok_or("only git commit signatures may be signed")?;
            let namespace = take_string(&mut data)?;
            if namespace != b"git" {
                return Err("only the git signature namespace may be signed".into());
            }
            Ok(())
        }
        Some(kind) => Err(format!("agent request type {kind} is not allowed")),
        None => Err("empty agent request".into()),
    }
}

fn take_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    if input.len() < 4 {
        return Err("truncated agent message".into());
    }
    let length = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    let value = input.get(4..4 + length).ok_or("truncated agent message")?;
    *input = &input[4 + length..];
    Ok(value)
}

/// Reads one length-prefixed agent message; `None` at a clean end.
pub fn read_message(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent message has an invalid length",
        ));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn write_message(stream: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let length = u32::try_from(body.len())
        .ok()
        .filter(|length| *length as usize <= MAX_MESSAGE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "agent message too large"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Sends one request to the agent at `socket` and returns its reply body,
/// after checking the request with [`permitted`].
pub fn relay(socket: &Path, message: &[u8]) -> io::Result<Vec<u8>> {
    if permitted(message).is_err() {
        return Ok(FAILURE[4..].to_vec());
    }
    let mut agent = UnixStream::connect(socket)?;
    agent.set_read_timeout(Some(Duration::from_secs(120)))?;
    write_message(&mut agent, message)?;
    read_message(&mut agent)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the agent closed"))
}

/// The backend's private agent socket for one commit. Dropping it removes
/// the socket and its directory.
pub struct AgentProxy {
    directory: PathBuf,
    socket: PathBuf,
    listener: UnixListener,
}

impl AgentProxy {
    /// Binds `agent.sock` in a new 0700 directory under `runtime`.
    pub fn bind(runtime: &Path) -> io::Result<Self> {
        let mut random = [0; 12];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = runtime.join(format!("nix-secrets-agent-{name}"));
        DirBuilder::new().mode(0o700).create(&directory)?;
        // The mode is applied again in case the umask narrowed nothing but a
        // parent ACL widened it.
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let socket = directory.join("agent.sock");
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_dir(&directory);
                return Err(error);
            }
        };
        let proxy = Self {
            directory,
            socket,
            listener,
        };
        fs::set_permissions(&proxy.socket, fs::Permissions::from_mode(0o600))?;
        proxy.listener.set_nonblocking(true)?;
        Ok(proxy)
    }

    pub fn path(&self) -> &Path {
        &self.socket
    }

    /// Relays agent requests through `forward` until `done` yields the
    /// result of the process that uses the socket.
    pub fn serve_until<T>(
        &self,
        done: &Receiver<T>,
        mut forward: impl FnMut(&[u8]) -> io::Result<Vec<u8>>,
    ) -> io::Result<T> {
        loop {
            match done.try_recv() {
                Ok(result) => return Ok(result),
                Err(TryRecvError::Disconnected) => {
                    return Err(io::Error::other("the signing process vanished"));
                }
                Err(TryRecvError::Empty) => {}
            }
            match self.listener.accept() {
                Ok((stream, _)) => self.serve_connection(stream, &mut forward)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn serve_connection(
        &self,
        mut stream: UnixStream,
        forward: &mut impl FnMut(&[u8]) -> io::Result<Vec<u8>>,
    ) -> io::Result<()> {
        let peer = socket_peercred(&stream).map_err(io::Error::from)?;
        if peer.uid != geteuid() {
            return Ok(());
        }
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        // A broken client connection only ends that connection.
        while let Ok(Some(message)) = read_message(&mut stream) {
            let reply = if permitted(&message).is_ok() {
                forward(&message)?
            } else {
                FAILURE[4..].to_vec()
            };
            if write_message(&mut stream, &reply).is_err() {
                break;
            }
        }
        Ok(())
    }
}

impl Drop for AgentProxy {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir(&self.directory);
    }
}

/// Where the backend creates its private agent directory.
pub fn runtime_directory() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_dir())
        .unwrap_or_else(std::env::temp_dir)
}

#[cfg(test)]
mod tests;
