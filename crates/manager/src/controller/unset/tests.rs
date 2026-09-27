//! Deploy-time generation against the real target generator, real age, and a
//! real backend store. Only the SSH hop is left out.

use super::*;
use nix_secrets_core::{Backend, SecretStore};
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_deploy::{run_value_generation, GenerationHost};
use serde_json::json;
use std::path::Path;
use std::process::Command;
use zeroize::Zeroizing;

struct Fixture {
    _temp: tempfile::TempDir,
    manifest: std::path::PathBuf,
    schema: Schema,
    identity: std::path::PathBuf,
    public_key: String,
    socket: std::path::PathBuf,
    store: std::path::PathBuf,
}

fn leaf(public_key: &str, name: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut value = json!({
        "kind": "secret", "recipientPublicKeys": [public_key], "recipientIds": ["operator"],
        "consumerUnits": [],
        "destination": {"path": format!("/persistent/secrets/app/service/{name}"),
            "category": "service", "owner": "root", "group": "root", "mode": "0400"}
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    value
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("id");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&identity)
        .status()
        .unwrap()
        .success());
    let public_key = std::fs::read_to_string(identity.with_extension("pub"))
        .unwrap()
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let socket = temp.path().join("backend.sock");
    let document = json!({"host": {
        "metadata": {"socketPath": socket,
            "deployment": {"host": "host", "destination": "forward@host", "port": 22}},
        "services": {"app": {
            "db-password": leaf(&public_key, "db-password", json!({"valueType": "password"})),
            "cookie": leaf(&public_key, "cookie", json!({"valueType": "key",
                "valueGenerator": {"kind": "random-bytes", "bytes": 32, "encoding": "base64url"}})),
            "entered": leaf(&public_key, "entered", json!({"valueType": "password"})),
            "provider": leaf(&public_key, "provider", json!({"valueType": "password",
                "externalInputRequired": true})),
            "opaque": leaf(&public_key, "opaque", json!({"valueType": "key"})),
            "shared": leaf(&public_key, "shared", json!({"valueType": "password",
                "generateOnDeploy": false})),
            "knot": leaf(&public_key, "knot", json!({"valueType": "key",
                "derivedFrom": {"identifier": "host.services.app.cookie",
                    "prefix": "secret: ", "suffix": "\n"}}))
        }}
    }});
    let manifest = temp.path().join("manifest.json");
    std::fs::write(&manifest, document.to_string()).unwrap();
    let schema = Schema::from_json(&document.to_string()).unwrap();
    let store = temp.path().join("nix-secrets.toml");
    Fixture {
        _temp: temp,
        manifest,
        schema,
        identity,
        public_key,
        socket,
        store,
    }
}

impl Fixture {
    fn controller(&self) -> Controller {
        let backend = Backend::bind(
            &self.socket,
            self.schema.clone(),
            SecretStore::new(&self.store),
        )
        .unwrap();
        std::thread::spawn(move || backend.serve());
        let stream = std::os::unix::net::UnixStream::connect(&self.socket).unwrap();
        Controller::new(
            crate::client::BackendClient::new(stream),
            self.schema.clone(),
            self.provider(),
            vec![],
        )
        .unwrap()
    }

    fn provider(&self) -> AgeCommandProvider {
        AgeCommandProvider::identity_file(&self.identity)
    }

    fn ids(names: &[&str]) -> Vec<String> {
        names
            .iter()
            .map(|name| format!("host.services.app.{name}"))
            .collect()
    }

    fn decrypt(&self, controller: &mut Controller, name: &str) -> Zeroizing<Vec<u8>> {
        SecretWriter::reveal(controller, &format!("host.services.app.{name}")).unwrap()
    }
}

/// The target side: kernel randomness replaced by OS randomness, and an
/// in-memory secret tree standing in for the installed generation.
#[derive(Default)]
struct Target {
    installed: BTreeMap<String, Vec<u8>>,
    versions: BTreeMap<String, String>,
    generated: usize,
}

impl GenerationHost for Target {
    fn mix(&mut self, contribution: &[u8]) -> Result<(), nix_secrets_deploy::DeployError> {
        assert_eq!(contribution.len(), 32);
        Ok(())
    }
    fn generate(
        &mut self,
        generator: &nix_secrets_core::DeployGenerator,
    ) -> Result<Zeroizing<Vec<u8>>, nix_secrets_deploy::DeployError> {
        self.generated += 1;
        generator
            .generate_with(&mut nix_secrets_core::generator::OsRandom)
            .map_err(nix_secrets_deploy::DeployError::Invalid)
    }
    fn fresh_version(&mut self) -> Result<[u8; 16], nix_secrets_deploy::DeployError> {
        let mut version = [0_u8; 16];
        getrandom::fill(&mut version).unwrap();
        Ok(version)
    }
    fn read_installed(
        &mut self,
        path: &Path,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, nix_secrets_deploy::DeployError> {
        Ok(self
            .installed
            .get(path.to_str().unwrap())
            .map(|value| Zeroizing::new(value.clone())))
    }
}

impl Target {
    /// Runs a deployment's generation step and installs the results.
    fn deploy(&mut self, fixture: &Fixture, plan: &UnsetPlan) -> BTreeMap<String, GeneratedRecord> {
        let entries = generate_entries(&fixture.schema, plan).unwrap();
        let versions = self.versions.clone();
        let derive = plan
            .derived_on_target
            .iter()
            .map(|(identifier, _)| identifier.clone())
            .collect::<Vec<_>>();
        let result = run_value_generation(
            &fixture.manifest,
            "host",
            &entries,
            &derive,
            &versions,
            // The target encrypts with plain age; it holds no identity.
            &AgeCommandProvider::new("age"),
            self,
        )
        .unwrap();
        for deployment in &result.deployments {
            let name = deployment.identifier.rsplit('.').next().unwrap();
            self.installed.insert(
                format!("/persistent/secrets/app/service/{name}"),
                STANDARD.decode(&deployment.contents_base64).unwrap(),
            );
            self.versions
                .insert(deployment.identifier.clone(), deployment.version_id.clone());
        }
        result.records
    }

    fn value(&self, name: &str) -> &[u8] {
        &self.installed[&format!("/persistent/secrets/app/service/{name}")]
    }
}

#[test]
fn unset_values_are_generated_on_the_target_stored_and_deployed() {
    let fixture = fixture();
    let mut controller = fixture.controller();
    SecretWriter::write(
        &mut controller,
        "host.services.app.entered",
        Zeroizing::new(b"entered-by-hand".to_vec()),
    )
    .unwrap();
    let set = controller
        .client
        .list()
        .unwrap()
        .into_keys()
        .collect::<BTreeSet<_>>();
    let before = controller
        .client
        .get(&SecretPath::parse("host.services.app.entered").unwrap())
        .unwrap()
        .unwrap()
        .version_id;
    let identifiers = Fixture::ids(&["db-password", "cookie", "entered"]);
    let plan = plan_unset(&fixture.schema, &identifiers, &set).unwrap();
    assert!(plan.missing.is_empty());
    assert_eq!(
        plan.generate,
        vec![
            (
                "host.services.app.db-password".to_string(),
                "password".to_string()
            ),
            (
                "host.services.app.cookie".to_string(),
                "32 random bytes, base64url".to_string()
            ),
        ]
    );
    let mut target = Target::default();
    let records = target.deploy(&fixture, &plan);
    assert_eq!(target.generated, 2);
    let stored = controller.store_generated(&records).unwrap();
    assert_eq!(stored.len(), 2);
    // The operator can decrypt exactly what the target installed.
    assert_eq!(
        fixture.decrypt(&mut controller, "db-password").as_slice(),
        target.value("db-password")
    );
    let cookie = fixture.decrypt(&mut controller, "cookie");
    assert_eq!(cookie.as_slice(), target.value("cookie"));
    assert_eq!(cookie.len(), 43);
    // The stored version is the version the target installed.
    let record = controller
        .client
        .get(&SecretPath::parse("host.services.app.db-password").unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        STANDARD.encode(&record.version_id),
        target.versions["host.services.app.db-password"]
    );
    // The existing value is never regenerated or rewritten.
    let after = controller
        .client
        .get(&SecretPath::parse("host.services.app.entered").unwrap())
        .unwrap()
        .unwrap()
        .version_id;
    assert_eq!(before, after);
    assert_eq!(
        fixture.decrypt(&mut controller, "entered").as_slice(),
        b"entered-by-hand"
    );
    // Once stored, nothing is left to generate.
    let set = controller
        .client
        .list()
        .unwrap()
        .into_keys()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        plan_unset(&fixture.schema, &identifiers, &set).unwrap(),
        UnsetPlan::default()
    );
}

#[test]
fn values_that_cannot_be_generated_are_all_listed_and_nothing_is_written() {
    let fixture = fixture();
    let mut controller = fixture.controller();
    let identifiers = Fixture::ids(&["db-password", "provider", "cookie", "opaque", "shared"]);
    let plan = plan_unset(&fixture.schema, &identifiers, &BTreeSet::new()).unwrap();
    let refusal = plan.refusal().unwrap();
    assert!(refusal.starts_with("Missing values that must be entered: "));
    for expected in [
        "host.services.app.provider (external input)",
        "host.services.app.opaque (no valueGenerator)",
        "host.services.app.shared (generateOnDeploy = false)",
    ] {
        assert!(refusal.contains(expected), "{refusal}");
    }
    assert!(!refusal.contains("db-password") && !refusal.contains("cookie"));
    // The approval shows the same list, and deploying refuses before it
    // connects: no active approval and an empty store are enough to prove it.
    let request = ApprovalRequest {
        id: "r".into(),
        target: "host".into(),
        secrets: identifiers,
        allow_partial: false,
    };
    let details = controller
        .approval_details(&request, None, &BTreeSet::new())
        .unwrap();
    assert_eq!(details.missing.len(), 3);
    assert_eq!(details.generate.len(), 2);
    assert!(controller.client.list().unwrap().is_empty());
}

#[test]
fn a_retry_after_a_lost_store_write_returns_the_installed_value() {
    let fixture = fixture();
    let mut controller = fixture.controller();
    let identifiers = Fixture::ids(&["db-password"]);
    let plan = plan_unset(&fixture.schema, &identifiers, &BTreeSet::new()).unwrap();
    let mut target = Target::default();
    // The first deployment's records are lost before they reach the store.
    let _lost = target.deploy(&fixture, &plan);
    let installed = target.value("db-password").to_vec();
    let records = target.deploy(&fixture, &plan);
    assert_eq!(target.generated, 1);
    assert!(records["host.services.app.db-password"].adopted);
    controller.store_generated(&records).unwrap();
    assert_eq!(
        fixture.decrypt(&mut controller, "db-password").as_slice(),
        installed.as_slice()
    );
}

#[test]
fn a_value_entered_during_deployment_is_kept() {
    let fixture = fixture();
    let mut controller = fixture.controller();
    let identifiers = Fixture::ids(&["db-password"]);
    let plan = plan_unset(&fixture.schema, &identifiers, &BTreeSet::new()).unwrap();
    let records = Target::default().deploy(&fixture, &plan);
    SecretWriter::write(
        &mut controller,
        "host.services.app.db-password",
        Zeroizing::new(b"typed-meanwhile".to_vec()),
    )
    .unwrap();
    let error = controller.store_generated(&records).unwrap_err();
    assert!(error.contains("entered in the store meanwhile"), "{error}");
    assert_eq!(
        fixture.decrypt(&mut controller, "db-password").as_slice(),
        b"typed-meanwhile"
    );
}

#[test]
fn records_for_other_recipients_are_rejected_without_decrypting() {
    let fixture = fixture();
    let identifiers = Fixture::ids(&["db-password"]);
    let plan = plan_unset(&fixture.schema, &identifiers, &BTreeSet::new()).unwrap();
    let mut records = Target::default().deploy(&fixture, &plan);
    let record = records.get_mut("host.services.app.db-password").unwrap();
    assert!(record_envelope(&fixture.schema, "host.services.app.db-password", record).is_ok());
    // Re-encrypt to another key: same shape, wrong recipient.
    let other = fixture._temp.path().join("other");
    Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&other)
        .status()
        .unwrap();
    let other_key = std::fs::read_to_string(other.with_extension("pub")).unwrap();
    let foreign = nix_secrets_crypto::encrypt_secret(
        "host.services.app.db-password",
        b"x",
        &[nix_secrets_crypto::Recipient {
            id: "operator",
            ssh_public_key: other_key.trim(),
        }],
        &AgeCommandProvider::new("age"),
    )
    .unwrap();
    record.age_ciphertext_base64 = STANDARD.encode(&foreign.age_ciphertext);
    let error =
        record_envelope(&fixture.schema, "host.services.app.db-password", record).unwrap_err();
    assert!(error.contains("recipient"), "{error}");
    record.recipient_ids = vec!["someone-else".into()];
    assert!(record_envelope(&fixture.schema, "host.services.app.db-password", record).is_err());
    let _ = fixture.public_key;
}

mod derived {
    use super::*;

    const KNOT_PREFIX: &str =
        "key:\n  - id: stalwart-dns\n    algorithm: hmac-sha256\n    secret: ";

    /// Two hosts: `mail` owns a raw TSIG secret, `dns` deploys it framed as
    /// a Knot key file.
    fn pair() -> (tempfile::TempDir, Schema, Controller) {
        let base = fixture();
        let key = base.public_key.clone();
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("backend.sock");
        let host = |name: &str, services: serde_json::Value| {
            json!({
                "metadata": {"socketPath": socket,
                    "deployment": {"host": name, "destination": format!("forward@{name}"), "port": 22}},
                "services": services
            })
        };
        let document = json!({
            "mail": host("mail", json!({"app": {
                "dns-update-key": leaf(&key, "dns-update-key", json!({"valueType": "key",
                    "valueGenerator": {"kind": "random-bytes", "bytes": 32, "encoding": "base64"}}))
            }})),
            "dns": host("dns", json!({"app": {
                "update-key": leaf(&key, "update-key", json!({"valueType": "key",
                    "derivedFrom": {"identifier": "mail.services.app.dns-update-key",
                        "prefix": KNOT_PREFIX, "suffix": "\n"}})),
                "transfer-key": leaf(&key, "transfer-key", json!({"valueType": "key",
                    "valueGenerator": {"kind": "random-bytes", "bytes": 32, "encoding": "base64"}})),
                "api-token": leaf(&key, "api-token", json!({"valueType": "password",
                    "externalInputRequired": true}))
            }}))
        });
        let schema = Schema::from_json(&document.to_string()).unwrap();
        let backend = Backend::bind(
            &socket,
            schema.clone(),
            SecretStore::new(temp.path().join("nix-secrets.toml")),
        )
        .unwrap();
        std::thread::spawn(move || backend.serve());
        let controller = Controller::new(
            crate::client::BackendClient::new(
                std::os::unix::net::UnixStream::connect(&socket).unwrap(),
            ),
            schema.clone(),
            AgeCommandProvider::identity_file(&base.identity),
            vec![],
        )
        .unwrap();
        // Keep the identity file alive with the fixture's temp directory.
        std::mem::forget(base);
        (temp, schema, controller)
    }

    const DERIVED: &str = "dns.services.app.update-key";
    const SOURCE: &str = "mail.services.app.dns-update-key";

    /// A symmetric secret of another host, unset: the host deployed first
    /// generates it with the source leaf's own generator, encrypts it to that
    /// leaf's recipients, and frames its derived value from it.
    #[test]
    fn an_unset_shared_source_is_generated_on_the_host_deployed_first() {
        let (_temp, schema, _controller) = pair();
        let plan = plan_unset(&schema, &[DERIVED.to_string()], &BTreeSet::new()).unwrap();
        assert!(plan.missing.is_empty(), "{:?}", plan.missing);
        assert_eq!(plan.shared.len(), 1);
        assert_eq!(plan.shared[0].0, SOURCE);
        assert_eq!(plan.derived_on_target, [(DERIVED.to_string(), SOURCE.to_string())]);
        let entries = generate_entries(&schema, &plan).unwrap();
        let shared = entries[0].shared.as_ref().expect("a shared source entry");
        assert_eq!(entries[0].identifier, SOURCE);
        // The owner's generator and recipients, from the operator's schema.
        let LeafSpec::Stored(owner) = schema.leaf(&SecretPath::parse(SOURCE).unwrap()).unwrap()
        else {
            panic!()
        };
        assert_eq!(shared.recipient_ids, owner.recipient_ids);
        assert_eq!(shared.generator, deployment_generator(&owner).unwrap().fingerprint());
    }

    /// Missing values never block: a manual value is listed with its reason
    /// and the rest deploys.
    #[test]
    fn missing_values_are_listed_and_never_block() {
        let (_temp, schema, _controller) = pair();
        let all = schema.deployable_identifiers("dns").unwrap();
        assert_eq!(all.len(), 3, "{all:?}");
        let plan = plan_unset(&schema, &all, &BTreeSet::new()).unwrap();
        assert_eq!(plan.missing.len(), 1);
        assert_eq!(plan.reasons["dns.services.app.api-token"], MissingKind::NeedsInput);
        assert!(plan.refusal_for(true).is_none());
        let refusal = plan.refusal_for(false).unwrap();
        assert!(refusal.contains("dns.services.app.api-token (external input)"), "{refusal}");
    }

    /// The deployment itself: the skipped value is left out of the target
    /// selection and named in the result the requester receives.
    #[test]
    fn a_partial_deployment_reports_what_it_skipped() {
        let summary = super::super::super::deployment_summary(
            "dns",
            &["dns.services.app.transfer-key".into()],
            &[DERIVED.into()],
            None,
        );
        assert!(summary.starts_with("deployed dns"), "{summary}");
        assert!(summary.contains("generated and stored: dns.services.app.transfer-key"));
        assert!(
            summary.contains(&format!(
                "not deployed yet, dns waits for: {DERIVED}"
            )),
            "{summary}"
        );
    }

    #[test]
    fn a_derived_value_is_its_framed_source_and_follows_it() {
        let (_temp, schema, mut controller) = pair();
        SecretWriter::write(
            &mut controller,
            SOURCE,
            Zeroizing::new(b"c2VjcmV0LXRzaWctYnl0ZXM=".to_vec()),
        )
        .unwrap();
        let set = controller.client.list().unwrap();
        let plan = plan_unset(
            &schema,
            &[DERIVED.to_string()],
            &set.keys().cloned().collect(),
        )
        .unwrap();
        assert_eq!(plan.refusal(), None);
        assert_eq!(
            plan.derived,
            vec![(DERIVED.to_string(), SOURCE.to_string())]
        );
        let entry = derive(&controller, DERIVED, SOURCE, &set).unwrap();
        assert_eq!(
            STANDARD.decode(&entry.contents_base64).unwrap(),
            format!("{KNOT_PREFIX}c2VjcmV0LXRzaWctYnl0ZXM=\n").into_bytes()
        );
        // The same source and framing give the same version; a new source
        // value gives a new one, so the target replaces the derived file.
        let again = derive(&controller, DERIVED, SOURCE, &set).unwrap();
        assert_eq!(entry.version_id, again.version_id);
        assert!(entry.version_id.starts_with("d-"));
        SecretWriter::write(&mut controller, SOURCE, Zeroizing::new(b"bmV3".to_vec())).unwrap();
        let set = controller.client.list().unwrap();
        let changed = derive(&controller, DERIVED, SOURCE, &set).unwrap();
        assert_ne!(entry.version_id, changed.version_id);
        assert!(STANDARD
            .decode(&changed.contents_base64)
            .unwrap()
            .ends_with(b"secret: bmV3\n"));
        // A derived value is never stored and never generated.
        assert!(
            SecretWriter::write(&mut controller, DERIVED, Zeroizing::new(b"x".to_vec())).is_err()
        );
        assert!(controller.client.list().unwrap().get(DERIVED).is_none());
    }

    #[test]
    fn schema_rejects_bad_sources() {
        let mut document: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&pair().1).unwrap()).unwrap();
        let derived = &mut document["dns"]["services"]["app"]["update-key"]["derivedFrom"];
        derived["identifier"] = json!("mail.services.app.absent");
        assert!(Schema::from_json(&document.to_string()).is_err());
        let derived = &mut document["dns"]["services"]["app"]["update-key"]["derivedFrom"];
        derived["identifier"] = json!(DERIVED);
        assert!(Schema::from_json(&document.to_string()).is_err());
        // A target manifest holds only its own host; a cross-host source is
        // then not checkable and is accepted.
        let derived = &mut document["dns"]["services"]["app"]["update-key"]["derivedFrom"];
        derived["identifier"] = json!(SOURCE);
        let only_dns = json!({"dns": document["dns"].clone()});
        assert!(Schema::from_json(&only_dns.to_string()).is_ok());
    }
}

#[test]
fn a_derived_value_and_its_unset_source_on_one_host_deploy_together() {
    let fixture = fixture();
    let mut controller = fixture.controller();
    let identifiers = Fixture::ids(&["cookie", "knot"]);
    let plan = plan_unset(&fixture.schema, &identifiers, &BTreeSet::new()).unwrap();
    assert_eq!(plan.refusal(), None);
    assert_eq!(
        plan.derived_on_target,
        vec![(
            "host.services.app.knot".to_string(),
            "host.services.app.cookie".to_string()
        )]
    );
    let mut target = Target::default();
    let records = target.deploy(&fixture, &plan);
    controller.store_generated(&records).unwrap();
    // The target installed the framed source, and the store holds only the
    // source: the operator decrypts exactly the bytes framed on the target.
    let cookie = fixture.decrypt(&mut controller, "cookie");
    assert_eq!(
        target.value("knot"),
        [b"secret: ".as_slice(), &cookie, b"\n"].concat()
    );
    assert!(controller
        .client
        .list()
        .unwrap()
        .get("host.services.app.knot")
        .is_none());
    // A later deployment derives from the stored source on the operator side
    // and yields the same bytes and version, so nothing changes on the host.
    let set = controller.client.list().unwrap();
    let plan = plan_unset(
        &fixture.schema,
        &identifiers,
        &set.keys().cloned().collect(),
    )
    .unwrap();
    assert!(plan.derived_on_target.is_empty());
    let entry = derive(&controller, "host.services.app.knot", "host.services.app.cookie", &set)
        .unwrap();
    assert_eq!(
        STANDARD.decode(&entry.contents_base64).unwrap(),
        target.value("knot")
    );
    assert_eq!(entry.version_id, target.versions["host.services.app.knot"]);
    // Without its source in the request, it still waits for the source.
    let plan = plan_unset(&fixture.schema, &Fixture::ids(&["knot"]), &BTreeSet::new()).unwrap();
    assert!(plan.refusal().unwrap().contains("deploy host first"));
}

/// ns1's deployment: a public default, a key inventory filled by other
/// hosts, a value entered by hand, and a key derived from another host.
mod ns1 {
    use super::*;

    fn ns1_schema() -> Schema {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
        let dest = |service: &str, name: &str| {
            json!({"path": format!("/persistent/secrets/{service}/service/{name}"),
                "category": "service", "owner": "root", "group": "root", "mode": "0400"})
        };
        let secret = |service: &str, name: &str, extra: serde_json::Value| {
            let mut value = json!({"kind": "secret", "recipientPublicKeys": [key],
                "recipientIds": ["operator"], "consumerUnits": [], "destination": dest(service, name)});
            value.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            value
        };
        let host = |name: &str, services: serde_json::Value| {
            json!({"metadata": {"socketPath": "/run/nix-secrets/backend.sock",
                "deployment": {"host": name, "destination": format!("forward@{name}"), "port": 22}},
                "services": services})
        };
        let mut known_hosts = dest("x", "y");
        known_hosts["path"] = json!("/persistent/public-info/storage-box/known-hosts");
        known_hosts["category"] = json!("public-info");
        known_hosts["mode"] = json!("0644");
        known_hosts["contentType"] = json!("ssh-known-hosts");
        let mut inventory = dest("report-authorized", "fault");
        inventory["contentType"] = json!("named-ssh-ed25519-public-keys");
        inventory["authorizedForUser"] = json!("report");
        let document = json!({
            "ns1": host("ns1", json!({
                "backup-public-info": {"storage-box-known-hosts": {
                    "kind": "public-info", "sharedPublicId": "storage-box/known-hosts",
                    "expectedSshHost": "box.example", "expectedSshPort": 23,
                    "installDefaultIfMissing": true, "recipientPublicKeys": [], "recipientIds": [],
                    "consumerUnits": [], "destination": known_hosts}},
                "report-authorized": {"fault": {"kind": "secret", "recipientPublicKeys": [key],
                    "recipientIds": ["operator"], "consumerUnits": [], "destination": inventory}},
                "authoritative-dns": {
                    "dyndns-update-key": secret("authoritative-dns", "dyndns-update-key",
                        json!({"valueType": "key", "generateOnDeploy": false})),
                    "update-key": secret("authoritative-dns", "update-key",
                        json!({"valueType": "key", "derivedFrom":
                            {"identifier": "hetzner2.services.stalwart.dns-update-key"}})),
                    "transfer-key": secret("authoritative-dns", "transfer-key",
                        json!({"valueType": "key", "valueGenerator":
                            {"kind": "random-bytes", "bytes": 32, "encoding": "base64"}}))
                }
            })),
            "hetzner2": host("hetzner2", json!({
                "stalwart": {"dns-update-key": secret("stalwart", "dns-update-key",
                    json!({"valueType": "key", "valueGenerator":
                        {"kind": "random-bytes", "bytes": 32, "encoding": "base64"}}))},
                "reporter": {"fault-key": {"kind": "generated", "recipientPublicKeys": [key],
                    "recipientIds": ["operator"], "consumerUnits": [],
                    "generatedSecret": {"type": "local-ssh-key", "output": dest("reporter", "fault-key"),
                        "bootstrap": null, "registerAt": "ns1.services.report-authorized.fault"}}}
            }))
        });
        Schema::from_json(&document.to_string()).unwrap()
    }

    #[test]
    fn classifies_each_unset_value_and_deploys_the_rest_when_partial() {
        let schema = ns1_schema();
        let all = schema.deployable_identifiers("ns1").unwrap();
        let plan = plan_unset(&schema, &all, &BTreeSet::new()).unwrap();
        // 1. Public information with a host default is not missing: the
        //    host keeps the default it installs.
        assert_eq!(plan.host_default, ["ns1.services.backup-public-info.storage-box-known-hosts"]);
        // 2. The inventory is filled by the hosts that register into it.
        let fault = "ns1.services.report-authorized.fault";
        assert_eq!(plan.reasons[fault], MissingKind::FilledByAnotherHost);
        let reason = &plan.missing.iter().find(|(id, _)| id == fault).unwrap().1;
        assert_eq!(reason, "filled when hetzner2 deploy");
        // 3. A value entered by hand is listed, not blocking.
        let manual = "ns1.services.authoritative-dns.dyndns-update-key";
        assert_eq!(plan.reasons[manual], MissingKind::NeedsInput);
        // 4. The symmetric TSIG secret of hetzner2 is generated on ns1,
        //    which deploys first, and the Knot file is framed from it.
        let source = "hetzner2.services.stalwart.dns-update-key";
        assert_eq!(plan.shared.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), [source]);
        assert!(plan
            .derived_on_target
            .contains(&("ns1.services.authoritative-dns.update-key".into(), source.into())));
        assert_eq!(plan.missing.len(), 2, "{:?}", plan.missing);
        assert!(plan.refusal_for(true).is_none());
        // A private key is only ever generated on its own host.
        assert!(shared_generator(&schema, "hetzner2.services.reporter.fault-key").is_none());
    }
}

/// Frames a derived value the way a deployment does: its source decrypted
/// in the deployment's batch.
fn derive(
    controller: &Controller,
    identifier: &str,
    source: &str,
    set: &BTreeMap<String, nix_secrets_core::EncryptedSecret>,
) -> Result<DeployEntry, String> {
    let derived = BTreeMap::from([(identifier.to_owned(), source.to_owned())]);
    let plaintexts = controller.decrypt_for_deployment(
        &[identifier.to_owned()],
        &BTreeSet::new(),
        &[],
        &derived,
        set,
    )?;
    controller.derived_entry(identifier, source, set, &plaintexts)
}

/// Every value a deployment decrypts, including a derived value's source,
/// goes through one launcher run: with 1Password, one authorization.
#[test]
fn a_deployment_decrypts_everything_in_one_provider_batch() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = fixture();
    let mut controller = fixture.controller();
    for (name, value) in [("entered", "one"), ("cookie", "two"), ("provider", "three")] {
        SecretWriter::write(
            &mut controller,
            &format!("host.services.app.{name}"),
            Zeroizing::new(value.as_bytes().to_vec()),
        )
        .unwrap();
    }
    // A launcher that counts its runs; it then runs the batch the way the
    // real one does (see tests/one_password_launcher.rs), here with a small
    // program that decodes the framing.
    let log = fixture._temp.path().join("launches");
    let launcher = fixture._temp.path().join("launcher");
    std::fs::write(
        &launcher,
        format!(
            "#!/bin/sh\necho \"$*\" >> {log}\n[ \"$1\" = --batch ] || exit 64\nshift\nexec perl {helper} \"$@\"\n",
            log = log.display(),
            helper = batch_helper(&fixture).display(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
    let provider = AgeCommandProvider::identity_file(&fixture.identity).through(&launcher, vec![]);
    controller.provider = provider;
    let entries = controller.client.list().unwrap();
    let identifiers = Fixture::ids(&["entered", "cookie", "provider", "knot"]);
    let derived = BTreeMap::from([(
        "host.services.app.knot".to_owned(),
        "host.services.app.cookie".to_owned(),
    )]);
    let values = controller
        .decrypt_for_deployment(&identifiers, &BTreeSet::new(), &[], &derived, &entries)
        .unwrap();
    assert_eq!(values.len(), 3, "the derived source is decrypted once");
    assert_eq!(values["host.services.app.entered"].as_slice(), b"one");
    assert_eq!(values["host.services.app.cookie"].as_slice(), b"two");
    assert_eq!(
        std::fs::read_to_string(&log).unwrap().lines().count(),
        1,
        "one launcher run for the whole deployment"
    );
}

/// A program run as `helper PROGRAM ARGS...` that reads length-framed
/// inputs on stdin, runs the program once per input and frames the outputs,
/// like `nix-secrets-1password --batch`.
fn batch_helper(fixture: &Fixture) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let helper = fixture._temp.path().join("batch-helper");
    // Perl is always present where the test suite runs (git depends on it).
    std::fs::write(
        &helper,
        r#"#!/usr/bin/env perl
use strict; use IPC::Open2;
binmode STDIN; binmode STDOUT; local $/;
my $in = <STDIN>; my $out = '';
while (length $in) {
  my $n = unpack('N', substr($in, 0, 4)); my $body = substr($in, 4, $n);
  $in = substr($in, 4 + $n);
  my $pid = open2(my $r, my $w, @ARGV); binmode $r; binmode $w;
  print $w $body; close $w; my $res = <$r>; $res = '' unless defined $res;
  waitpid($pid, 0); exit($? >> 8) if $?;
  $out .= pack('N', length $res) . $res;
}
print $out;
"#,
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    helper
}
