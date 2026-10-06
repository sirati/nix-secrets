mod common;

use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{ApprovalRequest, Backend, BackendEvent, Request, Response, SecretStore};
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
        allow_partial: false,
    };
    let mut submitter = UnixStream::connect(&socket).unwrap();
    assert!(matches!(
        call(&mut submitter, Request::SubmitApproval { request }),
        Response::ApprovalState { .. }
    ));
    for frontend in [&mut first, &mut second] {
        assert!(matches!(
            call(frontend, Request::PollApprovals),
            Response::Approvals { requests, .. } if requests.len() == 1
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
fn subscriber_receives_changes_without_polling() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("changes.sock");
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
    let mut watcher = UnixStream::connect(&socket).unwrap();
    watcher
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    assert!(matches!(
        call(&mut watcher, Request::SubscribeChanges),
        Response::Subscribed
    ));
    assert!(
        read_json::<Response>(&mut watcher).is_err(),
        "idle subscription received a poll frame"
    );

    let mut writer = UnixStream::connect(&socket).unwrap();
    assert!(matches!(
        call(
            &mut writer,
            Request::Set {
                path: common::path(),
                envelope: common::envelope("one")
            }
        ),
        Response::Updated
    ));
    assert!(matches!(
        read_json::<Response>(&mut watcher).unwrap(),
        Some(Response::Change { update: BackendEvent::SecretChanged { path, set: true } })
            if path == common::path().to_string()
    ));
    let approval = ApprovalRequest {
        id: "push-request".into(),
        target: "host".into(),
        secrets: vec![common::path().to_string()],
        allow_partial: false,
    };
    assert!(matches!(
        call(&mut writer, Request::SubmitApproval { request: approval }),
        Response::ApprovalState { .. }
    ));
    assert!(matches!(
        read_json::<Response>(&mut watcher).unwrap(),
        Some(Response::Change { update: BackendEvent::ApprovalRequested { request } })
            if request.id == "push-request"
    ));
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
        allow_partial: false,
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

#[test]
fn a_deployment_request_reaches_the_registered_frontend() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("deploy.sock");
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
    let mut requester = UnixStream::connect(&socket).unwrap();
    let deploy = || Request::RequestDeployment {
        target: "host".to_owned(),
        allow_partial: true,
        procedure: None,
    };
    // Nobody can answer yet: the request waits for a frontend instead of
    // being refused, and one that registers later is offered it.
    let Response::DeploymentRequested { request: early, waiting_for_operator: true } = call(&mut requester, deploy()) else {
        panic!("a deployment without a frontend was refused");
    };
    let mut frontend = UnixStream::connect(&socket).unwrap();
    assert!(matches!(
        call(&mut frontend, Request::RegisterFrontend),
        Response::FrontendRegistered
    ));
    let Response::Approvals { requests, .. } = call(&mut frontend, Request::PollApprovals) else {
        panic!("frontend cannot poll");
    };
    assert_eq!(requests, std::slice::from_ref(&early));
    assert!(matches!(
        call(&mut requester, Request::CancelApproval { request_id: early.id.clone() }),
        Response::ApprovalCancelled
    ));
    assert!(matches!(
        call(&mut requester, Request::RequestDeployment {
            target: "absent".to_owned(),
            allow_partial: false,
            procedure: None,
        }),
        Response::Error { message } if message.contains("not a host")
    ));
    let Response::DeploymentRequested { request, waiting_for_operator: false } = call(&mut requester, deploy()) else {
        panic!("deployment was not queued");
    };
    assert_eq!(request.target, "host");
    assert_eq!(request.secrets, [common::path().to_string()]);
    assert!(request.allow_partial);
    let Response::Approvals { requests, .. } = call(&mut frontend, Request::PollApprovals) else {
        panic!("frontend cannot poll");
    };
    assert_eq!(requests, std::slice::from_ref(&request));
    let Response::ApprovalClaimed { lease_id, .. } = call(
        &mut frontend,
        Request::ClaimApproval {
            request_id: request.id.clone(),
            lease_ms: 30_000,
        },
    ) else {
        panic!("frontend cannot claim");
    };
    assert!(matches!(
        call(&mut frontend, Request::ResolveApproval {
            request_id: request.id.clone(),
            lease_id,
            decision: nix_secrets_core::Decision::Approved,
            message: Some("deployed host".to_owned()),
        }),
        Response::ApprovalResolved
    ));
    // The requester reads the frontend's summary.
    assert!(matches!(
        call(&mut requester, Request::ApprovalStatus { request_id: request.id }),
        Response::ApprovalState {
            state: nix_secrets_core::ApprovalStatus::Resolved {
                decision: nix_secrets_core::Decision::Approved,
                message: Some(message),
            }
        } if message == "deployed host"
    ));
}

#[test]
fn persistent_backend_revalidates_public_info_against_current_trusted_schema() {
    use nix_secrets_core::{PublicInfoRecord, Schema, SecretPath};
    use std::sync::{Arc, Mutex};
    fn schema(host: &str) -> String {
        serde_json::json!({"host": {
            "metadata": {"socketPath":"/run/backend.sock", "deployment":{"host":"host","destination":"forward@host","port":22}},
            "services":{"backup":{"known-hosts":{
                "kind":"public-info", "sharedPublicId":"storage-box/known-hosts",
                "expectedSshHost":host, "expectedSshPort":23,
                "destination":{"path":"/persistent/public-info/storage-box/known-hosts","category":"public-info","owner":"root","group":"root","mode":"0644","contentType":"ssh-known-hosts"},
                "consumerUnits":[]
            }}}
        }}).to_string()
    }
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("reload.sock");
    let current = Arc::new(Mutex::new(Ok(schema("old.example"))));
    let loader = Arc::clone(&current);
    let backend = Backend::bind(&socket, Schema::from_json(&schema("old.example")).unwrap(),
        SecretStore::new(directory.path().join("nix-secrets.toml"))).unwrap()
        .with_schema_loader(move || {
            let input: String = loader.lock().unwrap().clone()?;
            Schema::from_json(&input).map_err(|error| error.to_string())
        });
    thread::spawn(move || backend.serve().unwrap());
    let mut stream = UnixStream::connect(socket).unwrap();
    let path = SecretPath::parse("host.services.backup.known-hosts").unwrap();
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJGP6rI+0vwLXEdrpE4Gptmg510lwiD0GHfr+ZX9CbCN";
    let record = |host: &str, version: &str| PublicInfoRecord {
        version_id: version.repeat(16), value: format!("[{host}]:23 {key}\n"),
    };
    assert!(matches!(call(&mut stream, Request::SetPublicInfoIfVersion {
        path: path.clone(), value: record("old.example", "01"), expected_version: None,
    }), Response::Updated));
    *current.lock().unwrap() = Ok(schema("new.example"));
    assert!(matches!(call(&mut stream, Request::SetPublicInfoIfVersion {
        path: path.clone(), value: record("new.example", "02"), expected_version: Some("01".repeat(16)),
    }), Response::Updated));
    assert!(matches!(call(&mut stream, Request::SetPublicInfoIfVersion {
        path: path.clone(), value: record("old.example", "03"), expected_version: Some("02".repeat(16)),
    }), Response::Error { .. }));
    *current.lock().unwrap() = Err("repository evaluation failed".to_owned());
    assert!(matches!(call(&mut stream, Request::RemovePublicInfoIfVersion {
        path, expected_version: "02".repeat(16),
    }), Response::Error { message } if message.contains("reloading repository schema failed")));
    assert!(matches!(call(&mut stream, Request::GetPublicInfo {
        shared_id: "storage-box/known-hosts".into(),
    }), Response::PublicInfo { value: Some(value) } if value == record("new.example", "02")));
}
