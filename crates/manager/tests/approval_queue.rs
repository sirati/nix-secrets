//! Real backend queues preserve simultaneous CLI deployments and key followups.
use nix_secrets_core::{
    framing::{read_json, write_json},
    ApprovalRequest, ApprovalStatus, Backend, Request, Response, Schema, SecretStore,
};
use nix_secrets_manager::client::BackendClient;
use std::{os::unix::net::UnixStream, time::Duration};

fn request(id: &str) -> ApprovalRequest {
    ApprovalRequest {
        id: id.into(),
        target: "ns1".into(),
        secrets: vec!["ns1.services.report.authorized".into()],
        allow_partial: false,
    }
}

#[test]
fn readiness_peeks_and_a_ns1_followup_do_not_strand_the_cli_deployment() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("backend.sock");
    let schema = Schema::from_json(&serde_json::json!({"ns1": {
        "metadata": {"socketPath": "/run/unused", "deployment":{"host":"unused","destination":"forward@unused","port":22}},
        "services":{"report":{"authorized":{"kind":"secret","recipientPublicKeys":["ssh-ed25519 test"],"recipientIds":["test"],"consumerUnits":[],"destination":{"path":"/persistent/secrets/report/service/authorized","category":"service","owner":"root","group":"root","mode":"0400"}}}}
    }}).to_string()).unwrap();
    let backend = Backend::bind(
        &socket,
        schema,
        SecretStore::new(root.path().join("secrets.toml")),
    )
    .unwrap();
    std::thread::spawn(move || backend.serve().unwrap());
    let connect = || {
        let stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        BackendClient::new(stream)
    };
    let mut ui = connect();
    ui.register_frontend().unwrap();
    let mut background = connect();
    background.register_frontend().unwrap();
    let mut cli = connect();
    let followup = request("pubkey-ns1-followup");
    cli.submit_approval(followup.clone()).unwrap();
    let deployment = cli.request_deployment("ns1", false).unwrap();
    assert!(ui.has_pending_approvals().unwrap());
    assert!(ui.has_pending_approvals().unwrap());
    assert!(background.has_pending_approvals().unwrap());
    let (first, first_lease) = ui.poll_and_claim().unwrap().unwrap();
    assert_eq!(first.id, followup.id);
    assert_eq!(
        cli.approval_status(&deployment.id).unwrap(),
        ApprovalStatus::Pending
    );
    ui.renew(first.id.clone(), first_lease).unwrap();
    ui.resolve(
        first.id,
        first_lease,
        true,
        Some("followup deployed".into()),
    )
    .unwrap();
    assert!(ui.has_pending_approvals().unwrap());
    let (second, second_lease) = ui.poll_and_claim().unwrap().unwrap();
    assert_eq!(second.id, deployment.id);
    assert!(matches!(
        cli.approval_status(&deployment.id).unwrap(),
        ApprovalStatus::Claimed { .. }
    ));
    ui.resolve(
        second.id,
        second_lease,
        true,
        Some("CLI deployment complete".into()),
    )
    .unwrap();
    assert!(matches!(
        cli.approval_status(&deployment.id).unwrap(),
        ApprovalStatus::Resolved { .. }
    ));
    assert!(!ui.has_pending_approvals().unwrap());
    assert!(!background.has_pending_approvals().unwrap());
}

#[test]
fn another_frontend_winning_the_first_claim_does_not_hide_the_second_candidate() {
    let (client, mut server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let first = request("pubkey-ns1-followup");
    let second = request("deploy-ns1-update");
    let expected = second.clone();
    let worker = std::thread::spawn(move || {
        assert!(matches!(
            read_json::<Request>(&mut server).unwrap(),
            Some(Request::PollApprovals)
        ));
        write_json(
            &mut server,
            &Response::Approvals {
                requests: vec![first.clone(), second.clone()],
            },
        )
        .unwrap();
        assert!(
            matches!(read_json::<Request>(&mut server).unwrap(), Some(Request::ClaimApproval {request_id,..}) if request_id == first.id)
        );
        write_json(
            &mut server,
            &Response::Error {
                message: "approval request is unavailable".into(),
            },
        )
        .unwrap();
        assert!(
            matches!(read_json::<Request>(&mut server).unwrap(), Some(Request::ClaimApproval {request_id,..}) if request_id == second.id)
        );
        write_json(
            &mut server,
            &Response::ApprovalClaimed {
                lease_id: 42,
                expires_in_ms: 300_000,
            },
        )
        .unwrap();
    });
    let mut client = BackendClient::new(client);
    let (claimed, lease) = client.poll_and_claim().unwrap().unwrap();
    assert_eq!(claimed, expected);
    assert_eq!(lease, 42);
    worker.join().unwrap();
}

#[test]
fn controller_reads_the_remaining_request_after_a_coalesced_background_notice() {
    use nix_secrets_crypto::AgeCommandProvider;
    use nix_secrets_manager::{controller::Controller, ui::SecretWriter};
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("backend.sock");
    let schema = Schema::from_json(&serde_json::json!({"ns1": {
        "metadata": {"socketPath": "/run/unused", "deployment":{"host":"unused","destination":"forward@unused","port":22}},
        "services":{"report":{"authorized":{"kind":"secret","recipientPublicKeys":["ssh-ed25519 test"],"recipientIds":["test"],"consumerUnits":[],"destination":{"path":"/persistent/secrets/report/service/authorized","category":"service","owner":"root","group":"root","mode":"0400"}}}}
    }}).to_string()).unwrap();
    let backend = Backend::bind(
        &socket,
        schema.clone(),
        SecretStore::new(root.path().join("secrets.toml")),
    )
    .unwrap();
    std::thread::spawn(move || backend.serve().unwrap());
    let connect = || {
        let stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        BackendClient::new(stream)
    };
    let mut controller = Controller::new(
        connect(),
        schema,
        AgeCommandProvider::identity_file(root.path().join("unused-identity")),
        vec![],
    )
    .unwrap();
    let mut cli = connect();
    cli.submit_approval(request("pubkey-ns1-followup")).unwrap();
    let deployment = cli.request_deployment("ns1", false).unwrap();
    // Both requests already exist before subscription: the background
    // readiness snapshot emits only one notification covering both.
    controller.start_background_refresh(socket);
    // The initial row snapshot is sent after the single readiness hint.
    // Waiting for it removes the scheduling race where that hint arrives
    // only after the first request was already claimed.
    let snapshot_deadline = std::time::Instant::now() + Duration::from_secs(3);
    while controller.refresh_rows().unwrap().is_none() {
        assert!(std::time::Instant::now() < snapshot_deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let next = |controller: &mut Controller| {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(request) = controller.poll_approval().unwrap() {
                break request;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "pending request lost after readiness notification"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    assert_eq!(next(&mut controller).id, "pubkey-ns1-followup");
    controller.approval(false).unwrap();
    assert_eq!(next(&mut controller).id, deployment.id);
    controller.approval(false).unwrap();
}
