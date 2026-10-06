//! Broker-backed failures before and after creating an active approval.
use super::*;
use nix_secrets_core::{ApprovalStatus, Backend, Decision, SecretStore};
use std::os::unix::net::UnixStream;

struct Fixture {
    root: tempfile::TempDir,
    socket: PathBuf,
    store: PathBuf,
    schema: Schema,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("backend.sock");
        let store = root.path().join("secrets.toml");
        let schema = Schema::from_json(&serde_json::json!({"ns1": {
            "metadata": {"socketPath": "/run/unused", "deployment": {"host": "unused", "destination": "forward@unused", "port": 22}},
            "services": {"report": {"authorized": {"kind": "secret", "recipientPublicKeys": ["ssh-ed25519 test"], "recipientIds": ["test"], "consumerUnits": [],
                "destination": {"path": "/persistent/secrets/report/service/authorized", "category": "service", "owner": "root", "group": "root", "mode": "0400"}}}}
        }}).to_string()).unwrap();
        let backend = Backend::bind(&socket, schema.clone(), SecretStore::new(&store)).unwrap();
        std::thread::spawn(move || backend.serve().unwrap());
        Self {
            root,
            socket,
            store,
            schema,
        }
    }
    fn client(&self) -> BackendClient {
        let stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        BackendClient::new(stream)
    }
    fn controller(&self) -> Controller {
        Controller::new(
            self.client(),
            self.schema.clone(),
            AgeCommandProvider::identity_file(self.root.path().join("unused-identity")),
            vec![],
        )
        .unwrap()
    }
}
fn request(id: &str) -> ApprovalRequest {
    ApprovalRequest {
        id: id.into(),
        target: "ns1".into(),
        secrets: vec!["ns1.services.report.authorized".into()],
        allow_partial: false,
    }
}
fn assert_rejected(client: &mut BackendClient, id: &str, error: &str) {
    assert_eq!(
        client.approval_status(id).unwrap(),
        ApprovalStatus::Resolved {
            decision: Decision::Rejected,
            message: Some(error.into())
        }
    );
}

#[test]
fn initial_plan_store_error_rejects_claim_without_dialog_and_queue_continues() {
    let fixture = Fixture::new();
    let mut controller = fixture.controller();
    let mut cli = fixture.client();
    let failed = request("pubkey-initial-plan-failure");
    cli.submit_approval(failed.clone()).unwrap();
    // Fail the real backend List call after claiming, while ResolveApproval
    // remains available: no replacement transport or secret provider needed.
    std::fs::write(&fixture.store, b"invalid { toml").unwrap();
    let error = controller.poll_approval_inner().unwrap_err();
    assert_rejected(&mut cli, &failed.id, &error);
    assert!(controller.active.is_none());
    std::fs::remove_file(&fixture.store).unwrap();
    let next = request("pubkey-next-after-plan-failure");
    cli.submit_approval(next.clone()).unwrap();
    assert_eq!(
        controller.poll_approval_inner().unwrap().unwrap().id,
        next.id
    );
    controller.approval_inner(false).unwrap();
    assert!(matches!(
        cli.approval_status(&next.id).unwrap(),
        ApprovalStatus::Resolved {
            decision: Decision::Rejected,
            ..
        }
    ));
}

#[test]
fn refreshed_details_error_clears_active_and_terminally_rejects_exact_claim() {
    let fixture = Fixture::new();
    let mut controller = fixture.controller();
    let mut cli = fixture.client();
    let failed = request("pubkey-details-failure");
    cli.submit_approval(failed.clone()).unwrap();
    let (claimed, lease_id) = controller.client.poll_and_claim().unwrap().unwrap();
    let expected = expected_target(&fixture.schema, &claimed).unwrap();
    controller.active = Some(ActiveApproval {
        request: claimed.clone(),
        lease_id,
        connection: Connection {
            name: "ns1".into(),
            destination: "forward@unused".into(),
            host: "unused".into(),
            port: 22,
            known_hosts: vec![],
            backend_route: None,
            identity_public_keys: vec![],
        },
        expected,
        identity: HostIdentity {
            host: "unused".into(),
            port: 22,
            keys: vec![],
            other_names_with_keys: vec![],
        },
        prepared: None,
        target_approved: true,
        renewed_at: Instant::now(),
        procedure: None,
        last_error: None,
        unchecked: BTreeSet::new(),
    });
    let state = TargetState {
        protocol_version: 4,
        hostname: "ns1".into(),
        secrets: vec![],
        tasks: vec![],
    };
    let set = claimed.secrets.iter().cloned().collect();
    let details = controller.approval_details(&claimed, Some(&state), &set);
    assert!(
        details.is_err(),
        "an omitted configured target leaf must fail"
    );
    let error = controller
        .finish_claimed_setup(&claimed, lease_id, details)
        .unwrap_err();
    assert!(error.contains("target omitted"));
    assert_rejected(&mut cli, &failed.id, &error);
    assert!(
        controller.active.is_none(),
        "failed setup cannot keep renewing a hidden dialog"
    );
    let next = request("pubkey-next-after-details-failure");
    cli.submit_approval(next.clone()).unwrap();
    assert_eq!(
        controller.poll_approval_inner().unwrap().unwrap().id,
        next.id
    );
    controller.approval_inner(false).unwrap();
}
