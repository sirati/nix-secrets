use super::{Request, Response};
use crate::SecretStore;
use crate::framing::{read_json, write_json};
use crate::git::agent::{AgentProxy, runtime_directory};
use crate::git::{CommitOptions, Repository};
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::mpsc;

pub(super) fn repository(store: &SecretStore) -> Result<Repository, String> {
    store
        .path()
        .parent()
        .map(Repository::new)
        .ok_or_else(|| "the store has no repository directory".into())
}

/// Runs a commit. With `forward_agent`, git signs through a private socket
/// whose requests travel to the frontend on `stream` and back.
pub(super) fn commit(
    stream: &mut UnixStream,
    store: &SecretStore,
    options: CommitOptions,
    forward_agent: bool,
) -> io::Result<Response> {
    let repository = match repository(store) {
        Ok(repository) => repository,
        Err(message) => return Ok(Response::Error { message }),
    };
    let result = if forward_agent {
        let proxy = match AgentProxy::bind(&runtime_directory()) {
            Ok(proxy) => proxy,
            Err(error) => {
                return Ok(Response::Error {
                    message: format!("cannot create the signing agent socket: {error}"),
                });
            }
        };
        let (done, finished) = mpsc::channel();
        let socket = proxy.path().to_owned();
        let directory = repository.directory().to_owned();
        std::thread::spawn(move || {
            let _ = done.send(Repository::new(directory).commit(&options, Some(&socket)));
        });
        // The proxy, and with it the socket, goes away when this returns.
        proxy.serve_until(&finished, |message| {
            write_json(
                stream,
                &Response::AgentRequest {
                    message: message.to_vec(),
                },
            )?;
            match read_json::<Request>(stream)? {
                Some(Request::AgentReply { message }) => Ok(message),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the frontend did not answer the agent request",
                )),
            }
        })?
    } else {
        repository.commit(&options, None)
    };
    Ok(match result {
        Ok(result) => Response::Committed { result },
        Err(message) => Response::Error { message },
    })
}
