//! Real backend and age registration regressions, without an SSH hop.
use super::*;
use nix_secrets_core::{ApprovalStatus, Backend, Decision, SecretStore};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::process::Command;

struct Fixture {
    _root: tempfile::TempDir,
    controller: Controller,
    identity: PathBuf,
    store: PathBuf,
    source: String,
}
impl Fixture {
    fn new(source: &str, second_target: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let identity = root.path().join("operator");
        assert!(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&identity)
                .status()
                .unwrap()
                .success()
        );
        let public = std::fs::read_to_string(identity.with_extension("pub"))
            .unwrap()
            .split_ascii_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let mut document = serde_json::json!({});
        for host in BTreeSet::from([source, "ns1", "ns2"]) {
            document[host] = serde_json::json!({
                "metadata":{"socketPath":"/run/unused", "deployment":{"host":host,"destination":format!("forward@{host}"),"port":22}},
                "services":{}
            });
        }
        for name in ["fault", "secretalert", "updatealert", "foreign"] {
            if name == "foreign" && !second_target {
                continue;
            }
            let target = if name == "foreign" { "ns2" } else { "ns1" };
            let destination = format!("{target}.services.report-authorized.{name}");
            document[source]["services"]["report"][name] = serde_json::json!({
                "kind":"generated", "recipientPublicKeys":[public], "recipientIds":["operator"], "consumerUnits":[],
                "generatedSecret":{"type":"local-ssh-key", "bootstrap":null, "registerAt":destination,
                    "output":{"path":format!("/persistent/secrets/report/service/{name}"),"category":"service","owner":"root","group":"root","mode":"0400","contentType":"openssh-private-key"}}
            });
            document[target]["services"]["report-authorized"][name] = serde_json::json!({
                "kind":"secret", "recipientPublicKeys":[public], "recipientIds":["operator"], "consumerUnits":[],
                "destination":{"path":format!("/persistent/secrets/report-authorized/service/{name}"),"category":"service","owner":"root","group":"root","mode":"0400","contentType":"named-ssh-ed25519-public-keys","authorizedForUser":name}
            });
        }
        for host in document
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
        {
            document[&host]["services"]["reporting-trust"]["receiver-known-hosts"] = serde_json::json!({
                "kind":"public-info", "recipientPublicKeys":[], "recipientIds":[], "consumerUnits":[], "optional":true,
                "sharedPublicId":"reporting/receiver-known-hosts", "expectedSshHost":"receiver.example",
                "expectedSshHosts":["127.0.0.1","2a01:4f8:1c17:5100::1"], "expectedSshPort":22,
                "destination":{"path":"/persistent/public-info/reporting/receiver-known-hosts","category":"public-info","owner":"root","group":"root","mode":"0644","contentType":"ssh-known-hosts"}
            });
        }
        document["ns1"]["metadata"]["deployment"]["publishHostIdentityTo"] =
            serde_json::json!("ns1.services.reporting-trust.receiver-known-hosts");
        document["ns1"]["metadata"]["deployment"]["port"] = serde_json::json!(23220);
        let schema = Schema::from_json(&document.to_string()).unwrap();
        let socket = root.path().join("backend.sock");
        let store = root.path().join("secrets.toml");
        let backend = Backend::bind(&socket, schema.clone(), SecretStore::new(&store)).unwrap();
        std::thread::spawn(move || backend.serve());
        let stream = UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let controller = Controller::new(
            BackendClient::new(stream),
            schema,
            AgeCommandProvider::identity_file(&identity),
            vec![],
        )
        .unwrap();
        Self {
            _root: root,
            controller,
            identity,
            store,
            source: source.into(),
        }
    }
    fn keys(&self, stamp: &str, byte: u8, foreign: bool) -> BTreeMap<String, String> {
        let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        blob.extend_from_slice(&[byte; 32]);
        ["fault", "secretalert", "updatealert", "foreign"]
            .into_iter()
            .filter(|name| *name != "foreign" || foreign)
            .map(|name| {
                (
                    format!("{}.services.report.{name}", self.source),
                    format!("{stamp} ssh-ed25519 {}", STANDARD.encode(&blob)),
                )
            })
            .collect()
    }
    fn prefetched(&mut self) -> BTreeMap<String, (Vec<u8>, Zeroizing<Vec<u8>>)> {
        let entries = self.controller.client.list().unwrap();
        entries
            .into_iter()
            .map(|(id, record)| {
                let envelope = EncryptedSecret {
                    format_version: record.format_version,
                    version_id: record.version_id.clone(),
                    recipient_ids: record.recipient_ids,
                    age_ciphertext: record.age_ciphertext,
                };
                let value = decrypt_secret(&id, &envelope, &self.controller.provider).unwrap();
                (id, (record.version_id, value))
            })
            .collect()
    }
}

#[test]
fn unchanged_keys_with_new_timestamps_do_not_encrypt_write_or_repeat_consent() {
    for source in ["sender", "ns1"] {
        let mut fixture = Fixture::new(source, false);
        let first = fixture.keys("20261005T120001123Z", 7, false);
        fixture
            .controller
            .register_public_keys(source, &first, &BTreeMap::new())
            .unwrap();
        let (request, lease) = fixture.controller.client.poll_and_claim().unwrap().unwrap();
        assert_eq!(request.target, "ns1");
        assert_eq!(
            request.secrets,
            ["fault", "secretalert", "updatealert"]
                .map(|name| format!("ns1.services.report-authorized.{name}"))
        );
        assert!(!request.allow_partial);
        assert!(
            fixture
                .controller
                .client
                .poll_and_claim()
                .unwrap()
                .is_none()
        );
        // Consent remains a real pending/claimed broker request, even on the
        // source host. Declining never silently applies this second send.
        fixture
            .controller
            .client
            .resolve(request.id.clone(), lease, false, None)
            .unwrap();
        assert!(matches!(
            fixture
                .controller
                .client
                .approval_status(&request.id)
                .unwrap(),
            ApprovalStatus::Resolved {
                decision: Decision::Rejected,
                ..
            }
        ));
        let prefetched = fixture.prefetched();
        let before = std::fs::read(&fixture.store).unwrap();
        let inode = std::fs::metadata(&fixture.store).unwrap().ino();
        fixture.controller.provider = AgeCommandProvider::with_identity_file(
            "/nonexistent/no-registration-crypto",
            &fixture.identity,
        );
        let repeat = fixture.keys("20261005T130002456Z", 7, false);
        fixture
            .controller
            .register_public_keys(source, &repeat, &prefetched)
            .unwrap();
        assert_eq!(std::fs::read(&fixture.store).unwrap(), before);
        assert_eq!(std::fs::metadata(&fixture.store).unwrap().ino(), inode);
        assert!(
            fixture
                .controller
                .client
                .poll_and_claim()
                .unwrap()
                .is_none()
        );
        fixture.controller.provider = AgeCommandProvider::identity_file(&fixture.identity);
        let rotated = fixture.keys("20261005T140003789Z", 9, false);
        fixture
            .controller
            .register_public_keys(source, &rotated, &prefetched)
            .unwrap();
        let (changed, _) = fixture.controller.client.poll_and_claim().unwrap().unwrap();
        assert_eq!(changed.target, "ns1");
        assert_eq!(changed.secrets, request.secrets);
        assert!(
            fixture
                .controller
                .client
                .poll_and_claim()
                .unwrap()
                .is_none()
        );
        for (_, (_, content)) in fixture.prefetched() {
            let content = std::str::from_utf8(&content).unwrap();
            assert!(content.contains("20261005T140003789Z"));
            assert!(!content.contains("20261005T120001123Z"));
        }
    }
}

#[test]
fn changed_destinations_require_one_separate_consent_per_target() {
    let mut fixture = Fixture::new("sender", true);
    let keys = fixture.keys("20261005T120001123Z", 7, true);
    fixture
        .controller
        .register_public_keys("sender", &keys, &BTreeMap::new())
        .unwrap();
    let (first, _) = fixture.controller.client.poll_and_claim().unwrap().unwrap();
    let (second, _) = fixture.controller.client.poll_and_claim().unwrap().unwrap();
    assert_eq!((first.target.as_str(), first.secrets.len()), ("ns1", 3));
    assert_eq!((second.target.as_str(), second.secrets.len()), ("ns2", 1));
    assert!(!first.allow_partial && !second.allow_partial);
    assert!(
        fixture
            .controller
            .client
            .poll_and_claim()
            .unwrap()
            .is_none()
    );
}

#[test]
fn invalid_returned_key_leaves_entire_public_mutation_batch_unwritten() {
    let mut fixture = Fixture::new("sender", false);
    let mut keys = fixture.keys("20261005T120001123Z", 7, false);
    keys.insert(
        "sender.services.report.secretalert".into(),
        "invalid target response".into(),
    );
    assert!(
        fixture
            .controller
            .register_public_keys("sender", &keys, &BTreeMap::new())
            .is_err()
    );
    assert!(
        fixture
            .controller
            .client
            .poll_and_claim()
            .unwrap()
            .is_none()
    );
    assert!(fixture.controller.client.list().unwrap().is_empty());
    assert!(
        fixture
            .controller
            .client
            .generated_public_key(&SecretPath::parse("sender.services.report.fault").unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn exact_host_matching_preserves_neighbouring_host_names() {
    let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    blob.extend_from_slice(&[7; 32]);
    let key = format!("ssh-ed25519 {}", STANDARD.encode(blob));
    let lines = format!(
        "node-extra-20261005T120001123Z {key}\nnode-20261005T120001123Z {key}\nother-20261005T120001123Z {key}\n"
    );
    assert_eq!(
        merge_named_key(&lines, "node", "node-20261005T140003789Z", &key),
        lines
    );
    let changed = merge_named_key(
        &lines,
        "node",
        "node-20261005T140003789Z",
        "ssh-ed25519 replacement",
    );
    assert!(changed.contains("node-extra-20261005T120001123Z"));
    assert!(changed.contains("other-20261005T120001123Z"));
    assert!(!changed.contains("\nnode-20261005T120001123Z"));
}

impl Fixture {
    fn staged(&mut self, byte: u8) -> super::host_mutations::HostMutationBatch {
        let mut batch = super::host_mutations::HostMutationBatch::default();
        let keys = self.keys("20261005T160003789Z", byte, false);
        let prefetched = self.prefetched();
        self.controller
            .stage_public_keys(&self.source, &keys, &prefetched, &mut batch)
            .unwrap();
        batch
    }
    fn pending(&mut self, batch: super::host_mutations::HostMutationBatch) -> String {
        let request = ApprovalRequest {
            id: format!(
                "deploy-test-{}",
                super::host_mutations::random_token().unwrap()
            ),
            target: self.source.clone(),
            secrets: self
                .keys("20261005T120001123Z", 1, false)
                .into_keys()
                .collect(),
            allow_partial: false,
        };
        self.controller
            .client
            .submit_approval(request.clone())
            .unwrap();
        let (claimed, lease_id) = self.controller.client.poll_and_claim().unwrap().unwrap();
        assert_eq!(claimed.id, request.id);
        self.controller.active = Some(ActiveApproval {
            expected: expected_target(&self.controller.schema, &claimed).unwrap(),
            request: claimed,
            lease_id,
            connection: Connection {
                name: self.source.clone(),
                destination: format!("forward@{}", self.source),
                host: self.source.clone(),
                port: 22,
                known_hosts: vec![],
                identity_public_keys: vec![],
            },
            identity: HostIdentity {
                host: self.source.clone(),
                port: 22,
                keys: vec![],
                other_names_with_keys: vec![],
            },
            prepared: None,
            target_approved: true,
            renewed_at: Instant::now(),
            last_error: None,
            unchecked: BTreeSet::new(),
        });
        let token = super::host_mutations::random_token().unwrap();
        self.controller.host_mutations = Some(super::host_mutations::PendingHostMutations {
            batch,
            request_id: self.controller.active.as_ref().unwrap().request.id.clone(),
            lease_id: self.controller.active.as_ref().unwrap().lease_id,
            token: token.clone(),
            generated: vec![],
            skipped: vec![],
        });
        token
    }
    fn seed_keys(&mut self) {
        let keys = self.keys("20261005T120001123Z", 7, false);
        self.controller
            .register_public_keys(&self.source, &keys, &BTreeMap::new())
            .unwrap();
        while let Some((request, lease)) = self.controller.client.poll_and_claim().unwrap() {
            self.controller
                .client
                .resolve(request.id, lease, false, None)
                .unwrap();
        }
    }
}
#[test]
fn rotated_metadata_and_nonempty_inventory_need_exact_review_and_denial_keeps_bytes() {
    let mut fixture = Fixture::new("sender", false);
    fixture.seed_keys();
    let before = std::fs::read(&fixture.store).unwrap();
    let batch = fixture.staged(9);
    assert_eq!(batch.reviews().len(), 6);
    assert_eq!(std::fs::read(&fixture.store).unwrap(), before);
    let token = fixture.pending(batch);
    assert!(
        fixture
            .controller
            .approve_host_mutations_inner(true, "different-review")
            .is_err()
    );
    assert_eq!(std::fs::read(&fixture.store).unwrap(), before);
    assert!(
        fixture
            .controller
            .approve_host_mutations_inner(false, &token)
            .unwrap()
            .is_none()
    );
    assert_eq!(std::fs::read(&fixture.store).unwrap(), before);
    assert!(
        fixture
            .controller
            .client
            .poll_and_claim()
            .unwrap()
            .is_none()
    );
}
#[test]
fn approved_batch_applies_once_and_groups_only_changed_destinations() {
    let mut fixture = Fixture::new("sender", false);
    fixture.seed_keys();
    let batch = fixture.staged(9);
    let token = fixture.pending(batch);
    fixture
        .controller
        .approve_host_mutations_inner(true, &token)
        .unwrap();
    assert!(
        fixture
            .controller
            .approve_host_mutations_inner(true, &token)
            .is_err()
    );
    let (request, _) = fixture.controller.client.poll_and_claim().unwrap().unwrap();
    assert_eq!(request.target, "ns1");
    assert_eq!(request.secrets.len(), 3);
    assert!(
        fixture
            .controller
            .client
            .poll_and_claim()
            .unwrap()
            .is_none()
    );
}
#[test]
fn concurrent_change_invalidates_review_without_rebase_or_other_writes() {
    let mut fixture = Fixture::new("sender", false);
    fixture.seed_keys();
    let batch = fixture.staged(9);
    let token = fixture.pending(batch);
    let path = SecretPath::parse("sender.services.report.fault").unwrap();
    let old = fixture
        .controller
        .client
        .generated_public_key(&path)
        .unwrap()
        .unwrap();
    let mut replacement = old.clone();
    replacement.version_id.push_str("-concurrent");
    fixture
        .controller
        .client
        .set_generated_public_key_if_version(&path, replacement, Some(old.version_id))
        .unwrap();
    let after = std::fs::read(&fixture.store).unwrap();
    assert!(
        fixture
            .controller
            .approve_host_mutations_inner(true, &token)
            .unwrap_err()
            .contains("changed after review")
    );
    assert_eq!(std::fs::read(&fixture.store).unwrap(), after);
    assert!(
        fixture
            .controller
            .client
            .poll_and_claim()
            .unwrap()
            .is_none()
    );
}
#[test]
fn public_key_results_outside_actual_task_selection_are_refused() {
    let fixture = Fixture::new("sender", false);
    let keys = fixture.keys("20261005T120001123Z", 7, false);
    let allowed = BTreeSet::from(["sender.services.report.fault".into()]);
    assert!(validate_returned_public_key_scope(&allowed, &keys).is_err());
    let only = keys
        .into_iter()
        .filter(|(id, _)| allowed.contains(id))
        .collect();
    validate_returned_public_key_scope(&allowed, &only).unwrap();
}

impl Fixture {
    fn trusted_identity(&self, byte: u8) -> HostIdentity {
        let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        blob.extend_from_slice(&[byte; 32]);
        HostIdentity {
            host: "ns1".into(),
            port: 23220,
            keys: vec![nix_secrets_transport::PresentedKey {
                algorithm: "ssh-ed25519".into(),
                encoded: STANDARD.encode(blob),
            }],
            other_names_with_keys: vec![],
        }
    }
    fn staged_identity(&mut self, byte: u8) -> super::host_mutations::HostMutationBatch {
        let mut batch = super::host_mutations::HostMutationBatch::default();
        let identity = self.trusted_identity(byte);
        self.controller
            .stage_host_identity("ns1", &identity, &mut batch)
            .unwrap();
        batch
    }
    fn initial_identity(&mut self) {
        let batch = self.staged_identity(7);
        assert!(batch.reviews().is_empty());
        self.controller.apply_host_mutations(batch).unwrap();
        while let Some((request, lease)) = self.controller.client.poll_and_claim().unwrap() {
            self.controller
                .client
                .resolve(request.id, lease, false, None)
                .unwrap();
        }
    }
}
#[test]
fn first_verified_identity_and_report_registration_share_one_consumer_request() {
    let mut fixture = Fixture::new("ns1", false);
    let mut batch = fixture.staged(7);
    let identity = fixture.trusted_identity(7);
    fixture
        .controller
        .stage_host_identity("ns1", &identity, &mut batch)
        .unwrap();
    assert!(batch.reviews().is_empty());
    assert!(
        fixture
            .controller
            .client
            .get_public_info("reporting/receiver-known-hosts")
            .unwrap()
            .is_none()
    );
    fixture.controller.apply_host_mutations(batch).unwrap();
    let record = fixture
        .controller
        .client
        .get_public_info("reporting/receiver-known-hosts")
        .unwrap()
        .unwrap();
    assert!(record.value.contains("receiver.example ssh-ed25519"));
    assert!(record.value.contains("2a01:4f8:1c17:5100::1 ssh-ed25519"));
    assert!(!record.value.contains(":23220"));
    let (request, lease) = fixture.controller.client.poll_and_claim().unwrap().unwrap();
    assert_eq!(request.target, "ns1");
    assert_eq!(request.secrets.len(), 4);
    assert!(
        request
            .secrets
            .contains(&"ns1.services.reporting-trust.receiver-known-hosts".into())
    );
    assert!(
        fixture
            .controller
            .client
            .poll_and_claim()
            .unwrap()
            .is_none(),
        "undeployed hosts receive no unsolicited connection requests"
    );
    fixture
        .controller
        .client
        .resolve(request.id, lease, false, None)
        .unwrap();
    let mut batch = fixture.staged(7);
    let identity = fixture.trusted_identity(7);
    fixture
        .controller
        .stage_host_identity("ns1", &identity, &mut batch)
        .unwrap();
    assert!(batch.mutations.is_empty());
    fixture.controller.apply_host_mutations(batch).unwrap();
    assert!(
        fixture
            .controller
            .client
            .poll_and_claim()
            .unwrap()
            .is_none()
    );
}
#[test]
fn host_identity_rotation_denial_preserves_record_and_acceptance_queues_consumer_consent() {
    let mut fixture = Fixture::new("ns1", false);
    fixture.initial_identity();
    let before = std::fs::read(&fixture.store).unwrap();
    let batch = fixture.staged_identity(9);
    assert_eq!(batch.reviews().len(), 1);
    assert_ne!(batch.reviews()[0].previous, batch.reviews()[0].proposed);
    let token = fixture.pending(batch);
    fixture
        .controller
        .approve_host_mutations_inner(false, &token)
        .unwrap();
    assert_eq!(std::fs::read(&fixture.store).unwrap(), before);
    assert!(
        fixture
            .controller
            .client
            .poll_and_claim()
            .unwrap()
            .is_none()
    );
    let batch = fixture.staged_identity(9);
    let token = fixture.pending(batch);
    fixture
        .controller
        .approve_host_mutations_inner(true, &token)
        .unwrap();
    assert_ne!(std::fs::read(&fixture.store).unwrap(), before);
    let (request, _) = fixture.controller.client.poll_and_claim().unwrap().unwrap();
    assert_eq!(request.target, "ns1");
    assert_eq!(
        request.secrets,
        ["ns1.services.reporting-trust.receiver-known-hosts"]
    );
    assert!(
        fixture
            .controller
            .client
            .poll_and_claim()
            .unwrap()
            .is_none()
    );
}
#[test]
fn identity_from_another_endpoint_is_never_published() {
    let mut fixture = Fixture::new("ns1", false);
    let mut identity = fixture.trusted_identity(7);
    identity.host = "attacker.example".into();
    let mut batch = super::host_mutations::HostMutationBatch::default();
    assert!(
        fixture
            .controller
            .stage_host_identity("ns1", &identity, &mut batch)
            .is_err()
    );
    assert!(batch.mutations.is_empty());
    assert!(
        fixture
            .controller
            .client
            .get_public_info("reporting/receiver-known-hosts")
            .unwrap()
            .is_none()
    );
}
#[test]
fn stale_batch_token_cannot_use_another_request_or_lease() {
    let mut fixture = Fixture::new("sender", false);
    fixture.seed_keys();
    let batch = fixture.staged(9);
    let token = fixture.pending(batch);
    let before = std::fs::read(&fixture.store).unwrap();
    let mut active = fixture.controller.active.take().unwrap();
    fixture
        .controller
        .client
        .resolve(active.request.id.clone(), active.lease_id, false, None)
        .unwrap();
    let mut second = active.request.clone();
    second.id.push_str("-second");
    fixture
        .controller
        .client
        .submit_approval(second.clone())
        .unwrap();
    let (claimed, lease_id) = fixture.controller.client.poll_and_claim().unwrap().unwrap();
    assert_eq!(claimed.id, second.id);
    active.request = claimed;
    active.lease_id = lease_id;
    fixture.controller.active = Some(active);
    assert!(
        fixture
            .controller
            .approve_host_mutations_inner(true, &token)
            .unwrap_err()
            .contains("another request or lease")
    );
    assert_eq!(std::fs::read(&fixture.store).unwrap(), before);
}
#[test]
fn disconnected_frontend_cannot_commit_previously_displayed_changes() {
    let mut fixture = Fixture::new("sender", false);
    fixture.seed_keys();
    let batch = fixture.staged(9);
    let token = fixture.pending(batch);
    let before = std::fs::read(&fixture.store).unwrap();
    let stream = UnixStream::connect(fixture._root.path().join("backend.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut replacement = BackendClient::new(stream);
    replacement.register_frontend().unwrap();
    drop(std::mem::replace(
        &mut fixture.controller.client,
        replacement,
    ));
    assert!(
        fixture
            .controller
            .approve_host_mutations_inner(true, &token)
            .unwrap_err()
            .contains("lease was lost")
    );
    assert_eq!(std::fs::read(&fixture.store).unwrap(), before);
    assert!(fixture.controller.host_mutations.is_none());
    assert!(fixture.controller.active.is_none());
}
#[test]
fn tokenless_deployment_confirmation_cannot_save_existing_host_values() {
    let mut fixture = Fixture::new("sender", false);
    fixture.seed_keys();
    let batch = fixture.staged(9);
    let _token = fixture.pending(batch);
    let before = std::fs::read(&fixture.store).unwrap();
    assert!(
        fixture
            .controller
            .approval(true)
            .unwrap_err()
            .contains("displayed review token")
    );
    assert_eq!(std::fs::read(&fixture.store).unwrap(), before);
}
#[test]
fn producer_ownership_and_shared_identity_uniqueness_are_validated() {
    let fixture = Fixture::new("ns1", false);
    let mut document = serde_json::to_value(&fixture.controller.schema).unwrap();
    document["ns2"]["metadata"]["deployment"]["publishHostIdentityTo"] =
        serde_json::json!("ns1.services.reporting-trust.receiver-known-hosts");
    assert!(
        Schema::from_json(&document.to_string()).is_err(),
        "another producer cannot publish through ns1's leaf"
    );
    document["ns2"]["metadata"]["deployment"]["publishHostIdentityTo"] =
        serde_json::json!("ns2.services.reporting-trust.receiver-known-hosts");
    assert!(
        Schema::from_json(&document.to_string()).is_err(),
        "a shared identity cannot have two producers"
    );
    document["ns2"]["metadata"]["deployment"]
        .as_object_mut()
        .unwrap()
        .remove("publishHostIdentityTo");
    document["ns2"]["services"]["reporting-trust"]["receiver-known-hosts"]["expectedSshPort"] =
        serde_json::json!(23);
    assert!(
        Schema::from_json(&document.to_string()).is_err(),
        "shared aliases must have identical validation"
    );
}

#[test]
fn expired_original_lease_cannot_commit_reviewed_values() {
    let mut fixture = Fixture::new("sender", false);
    fixture.seed_keys();
    let batch = fixture.staged(9);
    let token = fixture.pending(batch);
    let before = std::fs::read(&fixture.store).unwrap();
    let active = fixture.controller.active.as_ref().unwrap();
    fixture
        .controller
        .client
        .renew_for(active.request.id.clone(), active.lease_id, 1)
        .unwrap();
    std::thread::sleep(Duration::from_millis(5));
    assert!(
        fixture
            .controller
            .approve_host_mutations_inner(true, &token)
            .unwrap_err()
            .contains("lease was lost")
    );
    assert_eq!(std::fs::read(&fixture.store).unwrap(), before);
    assert!(fixture.controller.host_mutations.is_none());
    assert!(fixture.controller.active.is_none());
}
