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
fn later_invalid_key_does_not_lose_consent_for_already_saved_inventory() {
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
    let (request, _) = fixture.controller.client.poll_and_claim().unwrap().unwrap();
    assert_eq!(request.target, "ns1");
    assert_eq!(request.secrets, ["ns1.services.report-authorized.fault"]);
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
