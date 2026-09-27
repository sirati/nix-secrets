use super::*;
use nix::unistd::{getegid, geteuid, Group, User};
use serde_json::json;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

struct Fixture {
    _temp: tempfile::TempDir,
    manifest: std::path::PathBuf,
    secrets: Deployer,
    public: Deployer,
    secrets_root: std::path::PathBuf,
}

fn owner() -> (String, String) {
    (
        User::from_uid(geteuid()).unwrap().unwrap().name,
        Group::from_gid(getegid()).unwrap().unwrap().name,
    )
}

fn destination(
    service: &str,
    name: &str,
    mode: &str,
    extra: serde_json::Value,
) -> serde_json::Value {
    let (user, group) = owner();
    let mut value = json!({"path": format!("/persistent/secrets/{service}/service/{name}"),
        "category": "service", "owner": user, "group": group, "mode": mode});
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    value
}

fn leaf(name: &str, extra: serde_json::Value, content: serde_json::Value) -> serde_json::Value {
    let mut value = json!({
        "kind": "secret", "recipientPublicKeys": [KEY], "recipientIds": ["operator"],
        "consumerUnits": [], "destination": destination("app", name, "0440", content)
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    value
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let value = json!({"host": {
        "metadata": {"socketPath": "/run/backend.sock",
            "deployment": {"host": "host", "destination": "forward@host", "port": 22}},
        "services": {
            "app": {
                "explicit": leaf("explicit", json!({"valueType": "key"}), json!({})),
                "password": leaf("password", json!({"valueType": "password",
                    "consumerConstraints": {"cannotHandleLongerThan": 20, "matchingRegex": "[a-z]+"}}), json!({})),
                "cookie": leaf("cookie", json!({"valueType": "key", "valueGenerator": {
                    "kind": "random-bytes", "bytes": 32, "encoding": "hex",
                    "prefix": "C=", "suffix": "\n"}}), json!({})),
                "framed": leaf("framed", json!({"valueType": "key", "derivedFrom": {
                    "identifier": "host.services.app.password", "prefix": "pw=", "suffix": "\n"}}), json!({})),
                "remote": leaf("remote", json!({"valueType": "key", "derivedFrom": {
                    "identifier": "other.services.db.password", "prefix": "[", "suffix": "]"}}), json!({})),
                "external": leaf("external", json!({"valueType": "password", "externalInputRequired": true}), json!({})),
                "opaque": leaf("opaque", json!({"valueType": "key"}), json!({})),
                "private": leaf("private", json!({}), json!({"contentType": "openssh-private-key"})),
                "public": leaf("public", json!({}), json!({"contentType": "openssh-public-key"})),
                "named": leaf("named", json!({}), json!({"contentType": "named-ssh-ed25519-public-keys",
                    "authorizedForUser": "backup"})),
                "nested": {"deep": leaf("deep", json!({}), json!({}))}
            },
            "keys": {"local": {
                "kind": "generated", "recipientPublicKeys": [KEY], "recipientIds": ["operator"],
                "consumerUnits": [],
                "generatedSecret": {"type": "local-ssh-key", "bootstrap": null,
                    "output": destination("keys", "local", "0400", json!({}))}
            }},
            "signing": {"operator-key": {"kind": "operator", "recipientPublicKeys": [KEY],
                "recipientIds": ["operator"], "generator": {"installable": "x#y"}}}
        }
    }});
    let manifest = temp.path().join("manifest.json");
    std::fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    let secrets_root = temp.path().join("secrets");
    Fixture {
        secrets: Deployer::at(&secrets_root).unwrap(),
        public: Deployer::at(temp.path().join("public-info")).unwrap(),
        manifest,
        secrets_root,

        _temp: temp,
    }
}

fn values() -> BTreeMap<String, String> {
    BTreeMap::from([(
        "host.services.app.explicit".to_string(),
        "hello\n".to_string(),
    )])
}

fn read(root: &Path, relative: &str) -> String {
    std::fs::read_to_string(root.join(relative)).unwrap()
}

#[test]
fn installs_every_deployable_leaf_through_the_publisher() {
    let f = fixture();
    let report = mock_install(&f.manifest, "host", &values(), true, &f.secrets, &f.public).unwrap();
    assert_eq!(report.already_installed, 0);
    assert_eq!(report.installed.len(), 12);
    assert!(!report
        .installed
        .iter()
        .any(|id| id.contains("operator-key")));

    let root = &f.secrets_root;
    assert_eq!(read(root, "app/service/explicit"), "hello\n");
    let password = read(root, "app/service/password");
    assert!(password.len() == 20 && password.bytes().all(|b| b.is_ascii_lowercase()));
    let cookie = read(root, "app/service/cookie");
    assert!(cookie.starts_with("C=") && cookie.ends_with('\n') && cookie.len() == 2 + 64 + 1);
    // The derived value is its same-host source, framed exactly.
    assert_eq!(read(root, "app/service/framed"), format!("pw={password}\n"));
    let remote = read(root, "app/service/remote");
    assert!(remote.starts_with('[') && remote.ends_with(']') && remote.len() > 2);
    assert!(ssh_key::PrivateKey::from_openssh(read(root, "app/service/private")).is_ok());
    assert!(ssh_key::PrivateKey::from_openssh(read(root, "keys/service/local")).is_ok());
    assert!(ssh_key::PublicKey::from_openssh(read(root, "app/service/public").trim()).is_ok());
    let named = read(root, "app/service/named");
    assert!(named.starts_with("mock-") && named.contains(" ssh-ed25519 "));
    assert!(!read(root, "app/service/external").is_empty());
    assert!(!read(root, "app/service/deep").is_empty());

    // Declared modes, and versions like a real deployment.
    let meta = std::fs::metadata(root.join("keys/service/local")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o400);
    assert_eq!(meta.uid(), geteuid().as_raw());
    let meta = std::fs::metadata(root.join("app/service/explicit")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o440);
    let versions = f.secrets.current_versions().unwrap();
    let source_version = STANDARD
        .decode(&versions["host.services.app.password"])
        .unwrap();
    assert_eq!(source_version.len(), VERSION_ID_SIZE);
    let schema = load_schema(&f.manifest).unwrap();
    let nix_secrets_core::LeafSpec::Stored(framed) = schema
        .leaf(&SecretPath::parse("host.services.app.framed").unwrap())
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        versions["host.services.app.framed"],
        framed.derived_from.unwrap().version(&source_version)
    );
    assert!(f.public.current_versions().unwrap().is_empty());
}

#[test]
fn second_run_changes_nothing_and_only_missing_leaves_are_added() {
    let f = fixture();
    mock_install(&f.manifest, "host", &values(), true, &f.secrets, &f.public).unwrap();
    let before = f.secrets.current_versions().unwrap();
    let password = read(&f.secrets_root, "app/service/password");
    let current = std::fs::read_link(f.secrets_root.join(".current")).unwrap();
    let report = mock_install(&f.manifest, "host", &values(), true, &f.secrets, &f.public).unwrap();
    assert!(report.installed.is_empty());
    assert_eq!(report.already_installed, 12);
    assert_eq!(
        std::fs::read_link(f.secrets_root.join(".current")).unwrap(),
        current
    );
    assert_eq!(read(&f.secrets_root, "app/service/password"), password);
    assert_eq!(f.secrets.current_versions().unwrap(), before);
}

#[test]
fn an_explicit_value_for_a_derived_leaf_is_its_source_value() {
    let f = fixture();
    let values = BTreeMap::from([("host.services.app.remote".to_string(), "shared".to_string())]);
    mock_install(&f.manifest, "host", &values, true, &f.secrets, &f.public).unwrap();
    assert_eq!(read(&f.secrets_root, "app/service/remote"), "[shared]");
}

#[test]
fn unknown_and_operator_only_keys_are_refused() {
    let f = fixture();
    for key in [
        "host.services.app.nope",
        "host.services.signing.operator-key",
        "other.services.app.explicit",
    ] {
        let values = BTreeMap::from([(key.to_string(), "x".to_string())]);
        let error = mock_install(&f.manifest, "host", &values, true, &f.secrets, &f.public)
            .unwrap_err()
            .to_string();
        assert!(error.contains(key), "{error}");
    }
    assert!(f.secrets.current_versions().unwrap().is_empty());
}

#[test]
fn explicit_values_are_validated_like_deployed_ones() {
    let f = fixture();
    let values = BTreeMap::from([(
        "host.services.app.named".to_string(),
        "not a key".to_string(),
    )]);
    assert!(mock_install(&f.manifest, "host", &values, true, &f.secrets, &f.public).is_err());
    assert!(f.secrets.current_versions().unwrap().is_empty());
}

#[test]
fn public_information_gets_a_known_hosts_line_for_its_expected_endpoint() {
    let leaf: SecretLeaf = serde_json::from_value(json!({
        "kind": "public-info", "sharedPublicId": "box/known-hosts",
        "expectedSshHost": "box.example", "expectedSshPort": 23, "consumerUnits": [],
        "destination": {"path": "/persistent/public-info/box/known-hosts",
            "category": "public-info", "owner": "root", "group": "root", "mode": "0644"}
    }))
    .unwrap();
    let value = generate_stored("host.services.known.hosts", &leaf).unwrap();
    let text = std::str::from_utf8(&value).unwrap();
    nix_secrets_core::schema::validate_ssh_known_hosts(text, &["box.example"], 23).unwrap();
}

#[test]
fn without_generate_rest_every_leaf_without_a_value_is_listed() {
    let f = fixture();
    let values = BTreeMap::from([(
        "host.services.app.password".to_string(),
        "sourcevalue".to_string(),
    )]);
    let error = mock_install(&f.manifest, "host", &values, false, &f.secrets, &f.public)
        .unwrap_err()
        .to_string();
    for missing in [
        "host.services.app.cookie",
        "host.services.keys.local",
        "host.services.app.remote",
    ] {
        assert!(error.contains(missing), "{error}");
    }
    // The password is given, so its same-host derived value is not missing.
    assert!(!error.contains("host.services.app.password"), "{error}");
    assert!(!error.contains("host.services.app.framed"), "{error}");
    assert!(f.secrets.current_versions().unwrap().is_empty());
}

#[test]
fn a_derived_leaf_added_later_frames_the_installed_source() {
    let f = fixture();
    let values = BTreeMap::from([(
        "host.services.app.password".to_string(),
        "sourcevalue".to_string(),
    )]);
    mock_install(&f.manifest, "host", &values, true, &f.secrets, &f.public).unwrap();
    // A later configuration adds a second value derived from the same source.
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&f.manifest).unwrap()).unwrap();
    manifest["host"]["services"]["app"]["later"] = leaf(
        "later",
        json!({"valueType": "key", "derivedFrom": {
            "identifier": "host.services.app.password", "prefix": "<", "suffix": ">"}}),
        json!({}),
    );
    std::fs::write(&f.manifest, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let report = mock_install(&f.manifest, "host", &values, true, &f.secrets, &f.public).unwrap();
    assert_eq!(
        report.installed,
        vec!["host.services.app.later".to_string()]
    );
    assert_eq!(read(&f.secrets_root, "app/service/later"), "<sourcevalue>");
    let versions = f.secrets.current_versions().unwrap();
    let source = STANDARD
        .decode(&versions["host.services.app.password"])
        .unwrap();
    let derived: nix_secrets_core::DerivedFrom = serde_json::from_value(
        json!({"identifier": "host.services.app.password", "prefix": "<", "suffix": ">"}),
    )
    .unwrap();
    assert_eq!(
        versions["host.services.app.later"],
        derived.version(&source)
    );
}
