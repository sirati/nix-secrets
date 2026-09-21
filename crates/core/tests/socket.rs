mod common;

use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{ApprovalRequest, Backend, Request, Response, SecretStore};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

#[test]
fn creates_private_socket_and_serves_multiple_clients() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("backend.sock");
    let backend = match Backend::bind(
        &socket,
        common::schema(),
        SecretStore::new(directory.path().join("nix-secrets.toml")),
    ) {
        Ok(backend) => backend,
        // Some build sandboxes prohibit creating AF_UNIX filesystem sockets.
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("cannot bind test backend: {error}"),
    };
    let metadata = fs::metadata(&socket).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    thread::spawn(move || backend.serve().unwrap());

    let clients: Vec<_> = (0..6)
        .map(|_| {
            let socket = socket.clone();
            thread::spawn(move || {
                let mut stream = UnixStream::connect(socket).unwrap();
                write_json(&mut stream, &Request::List).unwrap();
                assert!(matches!(
                    read_json::<Response>(&mut stream).unwrap(),
                    Some(Response::Secrets { .. })
                ));
            })
        })
        .collect();
    for client in clients {
        client.join().unwrap();
    }
}

#[test]
fn refuses_to_replace_a_regular_file() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("backend.sock");
    fs::write(&socket, b"do not remove").unwrap();
    let result = Backend::bind(
        &socket,
        common::schema(),
        SecretStore::new(directory.path().join("nix-secrets.toml")),
    );
    assert!(result.is_err());
    assert_eq!(fs::read(&socket).unwrap(), b"do not remove");
}

#[test]
fn socket_frontends_receive_and_atomically_claim_an_approval() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("approval.sock");
    let backend = match Backend::bind(
        &socket,
        common::schema(),
        SecretStore::new(directory.path().join("nix-secrets.toml")),
    ) {
        Ok(backend) => backend,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("cannot bind test backend: {error}"),
    };
    thread::spawn(move || backend.serve().unwrap());
    let mut first = UnixStream::connect(&socket).unwrap();
    let mut second = UnixStream::connect(&socket).unwrap();
    assert!(matches!(
        call(&mut first, Request::RegisterFrontend),
        Response::FrontendRegistered
    ));
    assert!(matches!(
        call(&mut second, Request::RegisterFrontend),
        Response::FrontendRegistered
    ));
    let request = ApprovalRequest {
        id: "socket-request".to_owned(),
        target: "target.example".to_owned(),
        secrets: vec!["host.services.mail.service.password".to_owned()],
    };
    let mut submitter = UnixStream::connect(&socket).unwrap();
    assert!(matches!(
        call(&mut submitter, Request::SubmitApproval { request }),
        Response::ApprovalState { .. }
    ));
    for frontend in [&mut first, &mut second] {
        assert!(matches!(
            call(frontend, Request::PollApprovals),
            Response::Approvals { requests } if requests.len() == 1
        ));
    }
    let clients = [first, second].map(|mut stream| {
        thread::spawn(move || {
            let response = call(
                &mut stream,
                Request::ClaimApproval {
                    request_id: "socket-request".to_owned(),
                    lease_ms: Duration::from_secs(30).as_millis() as u64,
                },
            );
            (response, stream)
        })
    });
    let responses = clients.map(|client| client.join().unwrap());
    assert_eq!(
        responses
            .iter()
            .filter(|(response, _)| matches!(response, Response::ApprovalClaimed { .. }))
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|(response, _)| matches!(response, Response::Error { .. }))
            .count(),
        1
    );
}

fn call(stream: &mut UnixStream, request: Request) -> Response {
    write_json(stream, &request).unwrap();
    read_json(stream).unwrap().unwrap()
}

#[test]
fn socket_lease_renewal_rejects_an_expired_lease() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("renew.sock");
    let backend = match Backend::bind(
        &socket,
        common::schema(),
        SecretStore::new(directory.path().join("nix-secrets.toml")),
    ) {
        Ok(backend) => backend,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("cannot bind test backend: {error}"),
    };
    thread::spawn(move || backend.serve().unwrap());
    let mut frontend = UnixStream::connect(&socket).unwrap();
    assert!(matches!(
        call(&mut frontend, Request::RegisterFrontend),
        Response::FrontendRegistered
    ));
    let mut submitter = UnixStream::connect(&socket).unwrap();
    let request = ApprovalRequest {
        id: "renew-socket".to_owned(),
        target: "target.example".to_owned(),
        secrets: vec!["host.services.mail.service.password".to_owned()],
    };
    let _ = call(&mut submitter, Request::SubmitApproval { request });
    let lease_id = match call(
        &mut frontend,
        Request::ClaimApproval {
            request_id: "renew-socket".to_owned(),
            lease_ms: 20,
        },
    ) {
        Response::ApprovalClaimed { lease_id, .. } => lease_id,
        response => panic!("unexpected claim response: {response:?}"),
    };
    assert!(matches!(
        call(
            &mut frontend,
            Request::RenewApproval {
                request_id: "renew-socket".to_owned(),
                lease_id,
                lease_ms: 2,
            }
        ),
        Response::ApprovalRenewed { expires_in_ms: 2 }
    ));
    thread::sleep(Duration::from_millis(10));
    assert!(matches!(
        call(
            &mut frontend,
            Request::RenewApproval {
                request_id: "renew-socket".to_owned(),
                lease_id,
                lease_ms: 100,
            }
        ),
        Response::Error { .. }
    ));
}
