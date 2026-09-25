use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{ApprovalRequest, EncryptedSecret, Request, Response, SecretPath};
use serde_json::json;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn manifest(socket: &Path) -> String {
    json!({
        "host": {
            "metadata": { "socketPath": socket, "deployment": { "host": "host", "destination": "nix-secrets-forward@host", "port": 22 } },
            "services": {
                "mail": {
                    "password": {
                        "kind": "secret", "recipientPublicKeys": ["ssh-ed25519 AAAA test"],
                        "recipientIds": ["recipient"],
                        "destination": {
                            "path": "/persistent/secrets/mail/service/password",
                            "category": "service",
                            "owner": "mail",
                            "group": "mail",
                            "mode": "0400"
                        },
                        "consumerUnits": ["mail.service"]
                    }
                }
            }
        }
    })
    .to_string()
}

fn start(
    repository: &Path,
    socket: &Path,
    manifest_path: Option<&Path>,
    path: Option<&OsStr>,
) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nix-secrets-backend"));
    command
        .args(["--repository"])
        .arg(repository)
        .args(["--socket"])
        .arg(socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(manifest_path) = manifest_path {
        command.args(["--manifest"]).arg(manifest_path);
    }
    if let Some(path) = path {
        command.env("PATH", path);
    }
    command.spawn().unwrap()
}

fn await_socket(child: &mut Child, socket: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if socket
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_socket())
        {
            match UnixStream::connect(socket) {
                Ok(stream) => {
                    drop(stream);
                    return true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) => {}
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    return false;
                }
                Err(error) => panic!("backend socket could not be probed: {error}"),
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            let error = child
                .stderr
                .take()
                .map(|mut stderr| {
                    use std::io::Read;
                    let mut output = String::new();
                    let _ = stderr.read_to_string(&mut output);
                    output
                })
                .unwrap_or_default();
            if error.contains("Operation not permitted") {
                return false;
            }
            panic!("backend exited before readiness with {status}: {error}");
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("backend socket was not ready");
}

fn list(socket: &Path) -> Response {
    let mut stream = UnixStream::connect(socket).unwrap();
    write_json(&mut stream, &Request::List).unwrap();
    read_json(&mut stream).unwrap().unwrap()
}

fn call(stream: &mut UnixStream, request: Request) -> Response {
    write_json(stream, &request).unwrap();
    read_json(stream).unwrap().unwrap()
}

#[test]
fn concurrent_launches_share_the_live_approval_broker() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("backend.sock");
    let manifest_path = directory.path().join("manifest.json");
    fs::write(&manifest_path, manifest(&socket)).unwrap();

    let mut first = start(directory.path(), &socket, Some(&manifest_path), None);
    if !await_socket(&mut first, &socket) {
        return;
    }
    let original_inode = fs::metadata(&socket).unwrap().ino();
    let mut frontend_one = UnixStream::connect(&socket).unwrap();
    assert!(matches!(
        call(&mut frontend_one, Request::RegisterFrontend),
        Response::FrontendRegistered
    ));
    let approval = ApprovalRequest {
        id: "same-broker".into(),
        target: "target.example".into(),
        secrets: vec!["host.services.mail.password".into()],
    };
    let mut submitter = UnixStream::connect(&socket).unwrap();
    assert!(matches!(
        call(
            &mut submitter,
            Request::SubmitApproval { request: approval }
        ),
        Response::ApprovalState { .. }
    ));

    // A second launch sees the same live backend and must never unlink the
    // socket or create a second approval broker.
    let mut second = start(directory.path(), &socket, Some(&manifest_path), None);
    thread::sleep(Duration::from_millis(150));
    assert!(second.try_wait().unwrap().is_none());
    assert_eq!(fs::metadata(&socket).unwrap().ino(), original_inode);
    let mut frontend_two = UnixStream::connect(&socket).unwrap();
    assert!(matches!(
        call(&mut frontend_two, Request::RegisterFrontend),
        Response::FrontendRegistered
    ));
    assert!(matches!(
        call(&mut frontend_two, Request::PollApprovals),
        Response::Approvals { requests } if requests.len() == 1 && requests[0].id == "same-broker"
    ));

    first.kill().unwrap();
    first.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while second.try_wait().unwrap().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(second.try_wait().unwrap().is_some());
}

#[test]
fn attached_ssh_channel_exits_when_its_client_disconnects() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("backend.sock");
    let manifest_path = directory.path().join("manifest.json");
    fs::write(&manifest_path, manifest(&socket)).unwrap();
    let mut owner = start(directory.path(), &socket, Some(&manifest_path), None);
    if !await_socket(&mut owner, &socket) {
        return;
    }
    let inode = fs::metadata(&socket).unwrap().ino();
    let mut attached = Command::new(env!("CARGO_BIN_EXE_nix-secrets-backend"))
        .args(["--repository", directory.path().to_str().unwrap()])
        .args(["--socket", socket.to_str().unwrap()])
        .args(["--manifest", manifest_path.to_str().unwrap()])
        .arg("--hold-channel")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(150));
    assert!(attached.try_wait().unwrap().is_none());
    assert_eq!(fs::metadata(&socket).unwrap().ino(), inode);
    drop(attached.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(3);
    while attached.try_wait().unwrap().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(attached.try_wait().unwrap().is_some());
    assert!(owner.try_wait().unwrap().is_none());
    owner.kill().unwrap();
    owner.wait().unwrap();
}

#[test]
fn serves_multiple_clients_and_recovers_a_stale_socket() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("backend.sock");
    let manifest_path = directory.path().join("manifest.json");
    fs::write(&manifest_path, manifest(&socket)).unwrap();
    let mut backend = start(directory.path(), &socket, Some(&manifest_path), None);
    if !await_socket(&mut backend, &socket) {
        return;
    }

    let clients: Vec<_> = (0..6)
        .map(|_| {
            let socket = socket.clone();
            thread::spawn(move || assert!(matches!(list(&socket), Response::Secrets { .. })))
        })
        .collect();
    for client in clients {
        client.join().unwrap();
    }
    backend.kill().unwrap();
    backend.wait().unwrap();

    let mut replacement = start(directory.path(), &socket, Some(&manifest_path), None);
    assert!(await_socket(&mut replacement, &socket));
    assert!(matches!(list(&socket), Response::Secrets { .. }));
    replacement.kill().unwrap();
    replacement.wait().unwrap();
}

#[test]
fn evaluates_with_fixed_nix_arguments_and_persists_only_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let bin = directory.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let socket = directory.path().join("backend.sock");
    let generated = directory.path().join("generated.json");
    let invocation = directory.path().join("nix-arguments");
    fs::write(&generated, manifest(&socket)).unwrap();
    let nix = bin.join("nix");
    fs::write(
        &nix,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n[ \"$1\" = eval ] && [ \"$2\" = --json ] && [ \"$3\" = --no-write-lock-file ] && [ \"$4\" = '{}#nixSecretsSchemas' ] || exit 91\ncat '{}'\n",
            invocation.display(), directory.path().display(), generated.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&nix, fs::Permissions::from_mode(0o700)).unwrap();

    let search_path = std::env::join_paths(
        std::iter::once(bin.clone())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let mut backend = start(directory.path(), &socket, None, Some(&search_path));
    if !await_socket(&mut backend, &socket) {
        assert_eq!(
            fs::read_to_string(invocation).unwrap(),
            format!(
                "eval\n--json\n--no-write-lock-file\n{}#nixSecretsSchemas\n",
                directory.path().display()
            )
        );
        return;
    }
    let mut stream = UnixStream::connect(&socket).unwrap();
    let path = SecretPath::parse("host.services.mail.password").unwrap();
    let envelope = EncryptedSecret {
        format_version: 1,
        version_id: vec![7; 16],
        recipient_ids: vec!["recipient".into()],
        recipient_refs: vec![],
        age_ciphertext: b"age-encrypted-record".to_vec(),
        public_key: None,
    };
    write_json(&mut stream, &Request::Set { path, envelope }).unwrap();
    assert!(matches!(
        read_json(&mut stream).unwrap(),
        Some(Response::Updated)
    ));
    backend.kill().unwrap();
    backend.wait().unwrap();

    let store = fs::read_to_string(directory.path().join("nix-secrets.toml")).unwrap();
    assert!(store.contains("YWdlLWVuY3J5cHRlZC1yZWNvcmQ="));
    assert!(!store.contains("age-encrypted-record"));
}

#[path = "daemon/profiles.rs"]
mod profiles;
