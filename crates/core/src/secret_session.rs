//! A secret session: approved plaintexts held in memory and handed, one per
//! request, to the command that the session was opened for.
//!
//! The socket lives in a fresh 0700 directory under the runtime directory
//! and is 0600. Only processes of the same user that descend from the
//! session's owner (the `with-secrets` process, whose child is the command)
//! are answered. Only the approved identifiers can be fetched; anything else
//! is refused and never raises a new prompt. Dropping the session removes the
//! socket and erases every value.
use crate::framing::{read_json, write_json_sensitive};
use crate::private_socket::PrivateSocket;
use crate::secret_request::{SessionRequest, SessionResponse, is_same_or_descendant};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustix::net::sockopt::socket_peercred;
use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

pub struct SecretSession {
    socket: PrivateSocket,
    values: BTreeMap<String, Zeroizing<Vec<u8>>>,
    owner: u32,
}

impl SecretSession {
    /// Opens a session for `owner` and its descendants.
    pub fn bind(
        runtime: &Path,
        values: BTreeMap<String, Zeroizing<Vec<u8>>>,
        owner: u32,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: PrivateSocket::bind(runtime, "nix-secrets-session", "session.sock")?,
            values,
            owner,
        })
    }

    pub fn path(&self) -> &Path {
        self.socket.path()
    }

    /// Answers requests until `finished` returns true. It is polled between
    /// connections, at least every 20 ms while idle.
    pub fn serve_until(&self, mut finished: impl FnMut() -> bool) -> io::Result<()> {
        while !finished() {
            match self.socket.accept()? {
                Some(stream) => self.answer(stream),
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        Ok(())
    }

    /// Serves one request on one connection. A misbehaving client only loses
    /// its own connection.
    fn answer(&self, mut stream: UnixStream) {
        let permitted = socket_peercred(&stream).is_ok_and(|peer| {
            let pid = rustix::process::Pid::as_raw(Some(peer.pid)) as u32;
            is_same_or_descendant(pid, self.owner)
        });
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let response = match read_json::<SessionRequest>(&mut stream) {
            Ok(Some(_)) if !permitted => SessionResponse::Error {
                message: "this process was not started by the secret session's command".into(),
            },
            Ok(Some(SessionRequest::Get { identifier })) => match self.values.get(&identifier) {
                Some(value) => SessionResponse::Value {
                    value_base64: STANDARD.encode(value.as_slice()),
                },
                None => SessionResponse::Error {
                    message: format!(
                        "{identifier} was not part of the approved request; \
                         list it in `with-secrets` to ask for it"
                    ),
                },
            },
            _ => return,
        };
        let _ = write_json_sensitive(&mut stream, &response);
    }
}

/// Fetches one value from the session at `socket`. The socket and the
/// process serving it must belong to this user.
pub fn fetch(socket: &Path, identifier: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(socket)?;
    let uid = rustix::process::geteuid();
    if !metadata.file_type().is_socket() || metadata.uid() != uid.as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the secret session is not a socket of this user",
        ));
    }
    let mut stream = UnixStream::connect(socket)?;
    if socket_peercred(&stream).map_err(io::Error::from)?.uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the secret session is served by another user",
        ));
    }
    crate::framing::write_json(
        &mut stream,
        &SessionRequest::Get {
            identifier: identifier.to_owned(),
        },
    )?;
    match crate::framing::read_json_sensitive::<SessionResponse>(&mut stream)? {
        Some(SessionResponse::Value { ref value_base64 }) => STANDARD
            .decode(value_base64.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed session value")),
        Some(SessionResponse::Error { ref message }) => Err(io::Error::other(message.clone())),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the secret session closed",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves `session` until `client` has finished, and returns its result.
    fn serve_for<T: Send + 'static>(
        session: &SecretSession,
        client: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let client = std::thread::spawn(client);
        session.serve_until(|| client.is_finished()).unwrap();
        client.join().unwrap()
    }

    #[test]
    fn serves_approved_values_refuses_others_and_removes_its_socket() {
        let runtime = tempfile::tempdir().unwrap();
        let values = BTreeMap::from([(
            "host.services.a.key".to_owned(),
            Zeroizing::new(b"secret\0bytes".to_vec()),
        )]);
        let session = SecretSession::bind(runtime.path(), values, std::process::id()).unwrap();
        let socket = session.path().to_owned();
        let parent = socket.parent().unwrap().to_owned();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&parent).unwrap().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
        let client_socket = socket.clone();
        let (value, refused) = serve_for(&session, move || {
            (
                fetch(&client_socket, "host.services.a.key").map_err(|e| e.to_string()),
                fetch(&client_socket, "host.services.a.other").map_err(|e| e.to_string()),
            )
        });
        assert_eq!(value.unwrap().as_slice(), b"secret\0bytes");
        let refused = refused.unwrap_err();
        assert!(
            refused.contains("not part of the approved request"),
            "{refused}"
        );
        drop(session);
        assert!(!socket.exists());
        assert!(!parent.exists());
    }

    #[test]
    fn refuses_processes_outside_the_owners_tree() {
        let runtime = tempfile::tempdir().unwrap();
        let values = BTreeMap::from([("a.b.c.d".to_owned(), Zeroizing::new(b"v".to_vec()))]);
        // A child of this test: the test itself does not descend from it.
        let mut other = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let session = SecretSession::bind(runtime.path(), values, other.id()).unwrap();
        let socket = session.path().to_owned();
        let result = serve_for(&session, move || {
            fetch(&socket, "a.b.c.d")
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
        other.kill().unwrap();
        other.wait().unwrap();
        assert!(result.unwrap_err().contains("not started by"));
    }
}
