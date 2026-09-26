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
                "generateOnDeploy": false}))
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
        let entries = generate_entries(plan).unwrap();
        let versions = self.versions.clone();
        let result = run_value_generation(
            &fixture.manifest,
            "host",
            &entries,
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
                        "prefix": KNOT_PREFIX, "suffix": "\n"}}))
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

    #[test]
    fn an_unset_source_names_the_host_to_deploy_first() {
        let (_temp, schema, _controller) = pair();
        let plan = plan_unset(&schema, &[DERIVED.to_string()], &BTreeSet::new()).unwrap();
        let refusal = plan.refusal().unwrap();
        assert!(
            refusal.contains(&format!(
                "{DERIVED} (derived from unset {SOURCE}; deploy mail first, which generates it)"
            )),
            "{refusal}"
        );
        assert!(plan.generate.is_empty());
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
        let entry = controller.derived_entry(DERIVED, SOURCE, &set).unwrap();
        assert_eq!(
            STANDARD.decode(&entry.contents_base64).unwrap(),
            format!("{KNOT_PREFIX}c2VjcmV0LXRzaWctYnl0ZXM=\n").into_bytes()
        );
        // The same source and framing give the same version; a new source
        // value gives a new one, so the target replaces the derived file.
        let again = controller.derived_entry(DERIVED, SOURCE, &set).unwrap();
        assert_eq!(entry.version_id, again.version_id);
        assert!(entry.version_id.starts_with("d-"));
        SecretWriter::write(&mut controller, SOURCE, Zeroizing::new(b"bmV3".to_vec())).unwrap();
        let set = controller.client.list().unwrap();
        let changed = controller.derived_entry(DERIVED, SOURCE, &set).unwrap();
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
