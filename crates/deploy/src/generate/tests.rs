use super::*;
use nix_secrets_crypto::CryptoError;
use serde_json::json;
use std::cell::RefCell;

/// Records what it was asked to encrypt; the "ciphertext" is the plaintext
/// prefixed with the recipients so tests can inspect it.
#[derive(Default)]
struct Recording {
    calls: RefCell<Vec<(Vec<String>, Vec<u8>)>>,
}

impl CryptoProvider for Recording {
    fn encrypt(&self, recipients: &[&str], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.calls.borrow_mut().push((
            recipients.iter().map(|r| r.to_string()).collect(),
            plaintext.to_vec(),
        ));
        Ok(plaintext.to_vec())
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Ok(Zeroizing::new(ciphertext.to_vec()))
    }
}

#[derive(Default)]
struct FakeHost {
    mixed: Vec<Vec<u8>>,
    generated: usize,
    installed: BTreeMap<String, Vec<u8>>,
}

impl GenerationHost for FakeHost {
    fn mix(&mut self, contribution: &[u8]) -> Result<(), DeployError> {
        self.mixed.push(contribution.to_vec());
        Ok(())
    }
    fn generate(
        &mut self,
        generator: &nix_secrets_core::DeployGenerator,
    ) -> Result<Zeroizing<Vec<u8>>, DeployError> {
        self.generated += 1;
        generator
            .generate_with(&mut OsRandom)
            .map_err(DeployError::Invalid)
    }
    fn fresh_version(&mut self) -> Result<[u8; VERSION_ID_SIZE], DeployError> {
        Ok([7; VERSION_ID_SIZE])
    }
    fn read_installed(&mut self, path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, DeployError> {
        Ok(self
            .installed
            .get(path.to_str().unwrap())
            .map(|value| Zeroizing::new(value.clone())))
    }
}

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

fn manifest(temp: &tempfile::TempDir) -> std::path::PathBuf {
    let leaf = |name: &str, extra: serde_json::Value| {
        let mut value = json!({
            "kind": "secret", "recipientPublicKeys": [KEY], "recipientIds": ["operator"],
            "consumerUnits": [],
            "destination": {"path": format!("/persistent/secrets/app/service/{name}"),
                "category": "service", "owner": "root", "group": "root", "mode": "0400"}
        });
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        value
    };
    let value = json!({"host": {
        "metadata": {"socketPath": "/run/backend.sock",
            "deployment": {"host": "host", "destination": "forward@host", "port": 22}},
        "services": {"app": {
            "password": leaf("password", json!({"valueType": "password",
                "consumerConstraints": {"cannotHandleLongerThan": 20, "matchingRegex": "[a-z]+"}})),
            "tsig": leaf("tsig", json!({"valueType": "key", "valueGenerator": {
                "kind": "random-bytes", "bytes": 32, "encoding": "base64",
                "prefix": "key:\n  - id: t\n    algorithm: hmac-sha256\n    secret: ", "suffix": "\n"}})),
            "external": leaf("external", json!({"valueType": "password", "externalInputRequired": true})),
            "opaque": leaf("opaque", json!({"valueType": "key"}))
        }}
    }});
    let path = temp.path().join("manifest.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    path
}

fn entry(identifier: &str) -> GenerateEntry {
    GenerateEntry {
        identifier: identifier.into(),
        client_contribution_base64: STANDARD.encode([5_u8; 32]),
    }
}

#[test]
fn target_generates_installs_and_returns_only_ciphertext() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = manifest(&temp);
    let provider = Recording::default();
    let mut host = FakeHost::default();
    let result = run_value_generation(
        &manifest,
        "host",
        &[
            entry("host.services.app.password"),
            entry("host.services.app.tsig"),
        ],
        &BTreeMap::new(),
        &provider,
        &mut host,
    )
    .unwrap();
    assert_eq!(host.generated, 2);
    assert_eq!(host.mixed, vec![vec![5_u8; 32], vec![5_u8; 32]]);
    let password = result
        .deployments
        .iter()
        .find(|item| item.identifier == "host.services.app.password")
        .unwrap();
    let value = STANDARD.decode(&password.contents_base64).unwrap();
    assert_eq!(value.len(), 20);
    assert!(value.iter().all(u8::is_ascii_lowercase));
    let tsig = result
        .deployments
        .iter()
        .find(|item| item.identifier == "host.services.app.tsig")
        .unwrap();
    let tsig = String::from_utf8(STANDARD.decode(&tsig.contents_base64).unwrap()).unwrap();
    assert!(tsig.starts_with("key:\n  - id: t\n") && tsig.ends_with("=\n"));
    // Every value is encrypted to exactly the leaf's recipients, and the
    // record carries the version the target installs.
    let calls = provider.calls.borrow();
    assert!(calls.iter().all(|(recipients, _)| recipients == &[KEY]));
    let record = &result.records["host.services.app.password"];
    assert_eq!(record.version_id_base64, password.version_id);
    assert_eq!(record.recipient_ids, vec!["operator".to_string()]);
    assert!(!record.adopted);
    // The inner envelope binds the identifier and the version.
    let inner = STANDARD.decode(&record.age_ciphertext_base64).unwrap();
    assert!(inner.ends_with(&value));
    assert!(inner
        .windows(b"host.services.app.password".len())
        .any(|w| w == b"host.services.app.password"));
}

#[test]
fn retry_adopts_the_installed_value_instead_of_regenerating() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = manifest(&temp);
    let provider = Recording::default();
    let mut host = FakeHost::default();
    host.installed.insert(
        "/persistent/secrets/app/service/password".into(),
        b"alreadyinstalled".to_vec(),
    );
    let version = STANDARD.encode([9_u8; VERSION_ID_SIZE]);
    let installed = BTreeMap::from([("host.services.app.password".to_string(), version.clone())]);
    let result = run_value_generation(
        &manifest,
        "host",
        &[entry("host.services.app.password")],
        &installed,
        &provider,
        &mut host,
    )
    .unwrap();
    assert_eq!(host.generated, 0);
    assert!(host.mixed.is_empty());
    let record = &result.records["host.services.app.password"];
    assert!(record.adopted);
    assert_eq!(record.version_id_base64, version);
    assert_eq!(
        STANDARD
            .decode(&result.deployments[0].contents_base64)
            .unwrap(),
        b"alreadyinstalled"
    );
}

#[test]
fn values_without_a_known_format_or_supplied_externally_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = manifest(&temp);
    for identifier in ["host.services.app.external", "host.services.app.opaque"] {
        let mut host = FakeHost::default();
        let error = run_value_generation(
            &manifest,
            "host",
            &[entry(identifier)],
            &BTreeMap::new(),
            &Recording::default(),
            &mut host,
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("cannot be generated"), "{error}");
        assert_eq!(host.generated, 0);
    }
    assert!(run_value_generation(
        &manifest,
        "other",
        &[entry("host.services.app.password")],
        &BTreeMap::new(),
        &Recording::default(),
        &mut FakeHost::default(),
    )
    .is_err());
}
