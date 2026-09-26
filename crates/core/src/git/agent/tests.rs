use super::*;
use std::sync::{Arc, Mutex};

fn string(value: &[u8]) -> Vec<u8> {
    let mut output = (value.len() as u32).to_be_bytes().to_vec();
    output.extend_from_slice(value);
    output
}

fn sign_request(namespace: &str) -> Vec<u8> {
    let mut data = SSHSIG_MAGIC.to_vec();
    data.extend(string(namespace.as_bytes()));
    data.extend(string(b""));
    data.extend(string(b"sha512"));
    data.extend(string(&[0; 64]));
    let mut message = vec![SIGN_REQUEST];
    message.extend(string(b"key blob"));
    message.extend(string(&data));
    message.extend(0_u32.to_be_bytes());
    message
}

const ADD_IDENTITY: u8 = 17;

#[test]
fn the_filter_passes_only_listing_and_git_signatures() {
    assert!(permitted(&[REQUEST_IDENTITIES]).is_ok());
    assert!(permitted(&sign_request("git")).is_ok());
    assert!(permitted(&sign_request("file")).is_err());
    // An SSH login challenge is not an SSHSIG blob.
    let mut login = vec![SIGN_REQUEST];
    login.extend(string(b"key blob"));
    login.extend(string(b"session id and userauth request"));
    login.extend(0_u32.to_be_bytes());
    assert!(permitted(&login).is_err());
    for kind in [ADD_IDENTITY, 18, 19, 22, 23, 25, 27] {
        assert!(permitted(&[kind, 0, 0, 0, 0]).is_err(), "type {kind}");
    }
    assert!(permitted(&[]).is_err());
}

/// An agent that answers every request with SUCCESS and records it.
fn fake_agent(directory: &Path) -> (PathBuf, Arc<Mutex<Vec<u8>>>) {
    let socket = directory.join("fake-agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            while let Ok(Some(message)) = read_message(&mut stream) {
                record.lock().unwrap().push(message[0]);
                write_message(&mut stream, &[6]).unwrap();
            }
        }
    });
    (socket, seen)
}

#[test]
fn the_proxy_relays_signing_refuses_the_rest_and_removes_its_socket() {
    let directory = tempfile::tempdir().unwrap();
    let (agent, seen) = fake_agent(directory.path());
    let proxy = AgentProxy::bind(directory.path()).unwrap();
    let socket = proxy.path().to_owned();
    let parent = socket.parent().unwrap().to_owned();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);

    let (done, finished) = std::sync::mpsc::channel();
    let client_socket = socket.clone();
    std::thread::spawn(move || {
        let mut stream = UnixStream::connect(client_socket).unwrap();
        let mut replies = Vec::new();
        for request in [
            vec![REQUEST_IDENTITIES],
            sign_request("git"),
            vec![ADD_IDENTITY, 0, 0, 0, 0],
            vec![19],
        ] {
            write_message(&mut stream, &request).unwrap();
            replies.push(read_message(&mut stream).unwrap().unwrap()[0]);
        }
        done.send(replies).unwrap();
    });
    let replies = proxy
        .serve_until(&finished, |message| relay(&agent, message))
        .unwrap();
    assert_eq!(
        replies,
        [6, 6, 5, 5],
        "add and remove get SSH_AGENT_FAILURE"
    );
    assert_eq!(*seen.lock().unwrap(), [REQUEST_IDENTITIES, SIGN_REQUEST]);
    drop(proxy);
    assert!(!socket.exists());
    assert!(!parent.exists());
}
