use nix_secrets_core::{ApprovalBroker, ApprovalRequest, ApprovalStatus, BrokerError, Decision};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

fn request(id: &str) -> ApprovalRequest {
    ApprovalRequest {
        id: id.to_owned(),
        target: "host.example".to_owned(),
        secrets: vec!["host.services.mail.service.password".to_owned()],
        allow_partial: false,
    }
}

#[test]
fn broadcasts_to_every_registered_frontend() {
    let mut broker = ApprovalBroker::default();
    broker.register(10).unwrap();
    broker.register(11).unwrap();
    broker.submit(request("deploy-1")).unwrap();

    assert_eq!(broker.pending(10).unwrap(), vec![request("deploy-1")]);
    assert_eq!(broker.pending(11).unwrap(), vec![request("deploy-1")]);
    assert_eq!(broker.pending(10).unwrap(), vec![request("deploy-1")]);
}

#[test]
fn only_one_concurrent_frontend_can_claim() {
    let broker = Arc::new(Mutex::new(ApprovalBroker::default()));
    {
        let mut state = broker.lock().unwrap();
        state.register(1).unwrap();
        state.register(2).unwrap();
        state.submit(request("deploy-2")).unwrap();
    }
    let barrier = Arc::new(Barrier::new(3));
    let clients = [1, 2].map(|session| {
        let broker = Arc::clone(&broker);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            broker
                .lock()
                .unwrap()
                .claim(session, "deploy-2", Duration::from_secs(1))
        })
    });
    barrier.wait();
    let results = clients.map(|client| client.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(BrokerError::Unavailable)))
            .count(),
        1
    );
}

#[test]
fn expired_and_disconnected_leases_are_reclaimed() {
    let mut broker = ApprovalBroker::default();
    broker.register(1).unwrap();
    broker.register(2).unwrap();
    broker.submit(request("expires")).unwrap();
    broker
        .claim(1, "expires", Duration::from_millis(2))
        .unwrap();
    assert!(broker.pending(2).unwrap().is_empty());
    thread::sleep(Duration::from_millis(10));
    assert_eq!(broker.pending(2).unwrap(), vec![request("expires")]);
    assert!(broker.claim(2, "expires", Duration::from_secs(1)).is_ok());

    broker.submit(request("disconnects")).unwrap();
    broker
        .claim(1, "disconnects", Duration::from_secs(30))
        .unwrap();
    broker.disconnect(1);
    assert!(
        broker
            .claim(2, "disconnects", Duration::from_secs(1))
            .is_ok()
    );
}

#[test]
fn rejection_cancellation_and_reconnect_ids_are_stable() {
    let mut broker = ApprovalBroker::default();
    broker.register(1).unwrap();
    let original = request("stable-id");
    broker.submit(original.clone()).unwrap();
    let claim = broker
        .claim(1, "stable-id", Duration::from_secs(2))
        .unwrap();
    broker
        .resolve(1, "stable-id", claim.lease_id, Decision::Rejected, None)
        .unwrap();
    assert_eq!(
        broker.submit(original.clone()).unwrap(),
        ApprovalStatus::Resolved {
            decision: Decision::Rejected,
            message: None
        }
    );
    let mut collision = original;
    collision.target = "other.example".to_owned();
    assert!(matches!(
        broker.submit(collision),
        Err(BrokerError::Invalid(_))
    ));

    broker.submit(request("cancelled-id")).unwrap();
    broker.cancel("cancelled-id").unwrap();
    assert_eq!(
        broker.status("cancelled-id").unwrap(),
        ApprovalStatus::Cancelled
    );
    assert!(matches!(
        broker.claim(1, "cancelled-id", Duration::from_secs(1)),
        Err(BrokerError::Unavailable)
    ));
}

#[test]
fn reconnecting_frontend_receives_existing_pending_requests() {
    let mut broker = ApprovalBroker::default();
    broker.submit(request("while-offline")).unwrap();
    broker.register(50).unwrap();
    assert_eq!(broker.pending(50).unwrap(), vec![request("while-offline")]);
}

#[test]
fn lease_renewal_requires_the_live_owners_exact_lease() {
    let mut broker = ApprovalBroker::default();
    broker.register(1).unwrap();
    broker.register(2).unwrap();
    broker.submit(request("renewable")).unwrap();
    let claim = broker
        .claim(1, "renewable", Duration::from_millis(25))
        .unwrap();
    assert_eq!(
        broker
            .renew(1, "renewable", claim.lease_id, Duration::from_secs(2))
            .unwrap(),
        2_000
    );
    assert!(matches!(
        broker.renew(2, "renewable", claim.lease_id, Duration::from_secs(1)),
        Err(BrokerError::WrongLease)
    ));
    assert!(matches!(
        broker.renew(1, "renewable", claim.lease_id + 1, Duration::from_secs(1)),
        Err(BrokerError::WrongLease)
    ));

    broker.submit(request("expired-renewal")).unwrap();
    let expired = broker
        .claim(1, "expired-renewal", Duration::from_millis(2))
        .unwrap();
    thread::sleep(Duration::from_millis(10));
    assert!(matches!(
        broker.renew(
            1,
            "expired-renewal",
            expired.lease_id,
            Duration::from_secs(1)
        ),
        Err(BrokerError::WrongLease)
    ));
}

#[test]
fn peeking_and_claiming_a_followup_preserve_a_queued_deployment() {
    let mut broker = ApprovalBroker::default();
    broker.register(1).unwrap();
    broker.register(2).unwrap();
    broker.submit(request("pubkey-ns1-followup")).unwrap();
    broker.submit(request("deploy-ns1-update")).unwrap();
    let both = vec![request("pubkey-ns1-followup"), request("deploy-ns1-update")];
    assert_eq!(broker.pending(1).unwrap(), both);
    assert_eq!(broker.pending(1).unwrap(), both);
    let followup = broker
        .claim(1, "pubkey-ns1-followup", Duration::from_secs(30))
        .unwrap();
    assert_eq!(
        broker.pending(1).unwrap(),
        vec![request("deploy-ns1-update")]
    );
    assert_eq!(
        broker.pending(2).unwrap(),
        vec![request("deploy-ns1-update")]
    );
    broker
        .renew(
            1,
            "pubkey-ns1-followup",
            followup.lease_id,
            Duration::from_secs(30),
        )
        .unwrap();
    assert!(matches!(
        broker.resolve(
            2,
            "pubkey-ns1-followup",
            followup.lease_id,
            Decision::Approved,
            None
        ),
        Err(BrokerError::WrongLease)
    ));
    broker
        .resolve(
            1,
            "pubkey-ns1-followup",
            followup.lease_id,
            Decision::Approved,
            None,
        )
        .unwrap();
    assert_eq!(
        broker.pending(1).unwrap(),
        vec![request("deploy-ns1-update")]
    );
    broker.cancel("deploy-ns1-update").unwrap();
    assert!(broker.pending(1).unwrap().is_empty());
    assert!(broker.pending(2).unwrap().is_empty());
}

#[test]
fn a_claim_pruned_by_readers_returns_when_its_owner_disconnects() {
    let mut broker = ApprovalBroker::default();
    broker.register(1).unwrap();
    broker.register(2).unwrap();
    broker.submit(request("requeued")).unwrap();
    broker
        .claim(1, "requeued", Duration::from_secs(30))
        .unwrap();
    assert!(broker.pending(2).unwrap().is_empty());
    broker.disconnect(1);
    assert_eq!(broker.pending(2).unwrap(), vec![request("requeued")]);
}

#[test]
fn resolved_success_is_never_pending_or_claimable_after_disconnect_and_reregister() {
    let mut broker=ApprovalBroker::default();broker.register(1).unwrap();
    broker.submit(request("pubkey-completed")).unwrap();
    let claim=broker.claim(1,"pubkey-completed",Duration::from_secs(1)).unwrap();
    broker.resolve(1,"pubkey-completed",claim.lease_id,Decision::Approved,None).unwrap();
    broker.disconnect(1);broker.register(2).unwrap();
    assert!(broker.pending(2).unwrap().is_empty());
    assert!(matches!(broker.claim(2,"pubkey-completed",Duration::from_secs(1)),Err(BrokerError::Unavailable)));
    broker.submit(request("pubkey-new")).unwrap();
    assert_eq!(broker.pending(2).unwrap(),vec![request("pubkey-new")]);
}
