use base64::{engine::general_purpose::STANDARD, Engine};
use nix::unistd::{getegid, geteuid, Group, User};
use nix_secrets_deploy::{
    load_and_validate_manifest, load_target_state, Deployer, DeploymentBatch, SecretDeployment,
};
use serde_json::json;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn account_names() -> (String, String) {
    let user = User::from_uid(geteuid()).unwrap().unwrap().name;
    let group = Group::from_gid(getegid()).unwrap().unwrap().name;
    (user, group)
}

fn request(identifier: &str, contents: &[u8]) -> SecretDeployment {
    SecretDeployment {
        identifier: identifier.into(),
        version_id: "version-one".into(),
        contents_base64: STANDARD.encode(contents),
    }
}

fn manifest(temp: &tempfile::TempDir, mode: &str) -> std::path::PathBuf {
    let (owner, group) = account_names();
    let value = json!({"testhost": {
        "metadata": {"socketPath": "/persistent/secrets/backend.sock",
            "deployment": {"host": "testhost", "destination": "secrets@testhost", "port": 22}},
        "services": {"mail": {"password": {
            "kind": "secret", "recipientPublicKeys": ["ssh-ed25519 test"], "recipientIds": ["key"],
            "consumerUnits": ["mail.service"],
            "destination": {"path": "/persistent/secrets/mail/service/password",
                "category": "service", "owner": owner, "group": group, "mode": mode}
        }}, "git": {"token": {
            "kind": "secret", "recipientPublicKeys": ["ssh-ed25519 test"], "recipientIds": ["key"],
            "consumerUnits": ["git.service"],
            "destination": {"path": "/persistent/secrets/git/service/token",
                "category": "service", "owner": owner, "group": group, "mode": mode}
        }}}
    }});
    let path = temp.path().join("manifest.json");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    path
}

#[test]
fn manifest_is_authoritative_for_destination_and_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let path = manifest(&temp, "0440");
    let batch = DeploymentBatch {
        version: 1,
        requested_identifiers: vec!["testhost.services.mail.password".into()],
        entries: vec![request("testhost.services.mail.password", b"secret")],
    };
    let resolved = load_and_validate_manifest(&path, "testhost", &batch).unwrap();
    let root = temp.path().join("secrets");
    let deployer = Deployer::at(&root).unwrap();
    deployer.deploy(&resolved).unwrap();
    let output = root.join("mail/service/password");
    assert_eq!(fs::read(&output).unwrap(), b"secret");
    let metadata = fs::metadata(&output).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o440);
    assert_eq!(metadata.uid(), geteuid().as_raw());
    let state =
        load_target_state(&path, "testhost", &deployer.current_versions().unwrap()).unwrap();
    assert_eq!(state.secrets.len(), 2);
    assert_eq!(
        state
            .secrets
            .iter()
            .find(|secret| secret.identifier.ends_with("mail.password"))
            .unwrap()
            .current_version_id
            .as_deref(),
        Some("version-one")
    );
    assert!(state
        .secrets
        .iter()
        .find(|secret| secret.identifier.ends_with("git.token"))
        .unwrap()
        .current_version_id
        .is_none());

    let git = DeploymentBatch {
        version: 1,
        requested_identifiers: vec!["testhost.services.git.token".into()],
        entries: vec![request("testhost.services.git.token", b"git-secret")],
    };
    deployer
        .deploy(&load_and_validate_manifest(&path, "testhost", &git).unwrap())
        .unwrap();
    assert_eq!(fs::read(&output).unwrap(), b"secret");
    assert_eq!(
        fs::read(root.join("git/service/token")).unwrap(),
        b"git-secret"
    );
}

#[test]
fn rejects_omissions_extras_duplicates_and_bad_modes_before_deploy() {
    let temp = tempfile::tempdir().unwrap();
    let path = manifest(&temp, "0400");
    let empty = DeploymentBatch {
        version: 1,
        requested_identifiers: vec![],
        entries: vec![],
    };
    assert!(load_and_validate_manifest(&path, "testhost", &empty).is_err());
    let extra = DeploymentBatch {
        version: 1,
        requested_identifiers: vec!["testhost.services.mail.password".into()],
        entries: vec![
            request("testhost.services.mail.password", b"one"),
            request("testhost.services.mail.other", b"two"),
        ],
    };
    assert!(load_and_validate_manifest(&path, "testhost", &extra).is_err());
    let duplicate = DeploymentBatch {
        version: 1,
        requested_identifiers: vec![
            "testhost.services.mail.password".into(),
            "testhost.services.mail.password".into(),
        ],
        entries: vec![
            request("testhost.services.mail.password", b"one"),
            request("testhost.services.mail.password", b"two"),
        ],
    };
    assert!(load_and_validate_manifest(&path, "testhost", &duplicate).is_err());
    let bad_path = manifest(&temp, "0777");
    let complete = DeploymentBatch {
        version: 1,
        requested_identifiers: vec!["testhost.services.mail.password".into()],
        entries: vec![request("testhost.services.mail.password", b"one")],
    };
    assert!(load_and_validate_manifest(&bad_path, "testhost", &complete).is_err());
}

#[test]
fn generated_output_uses_manifest_and_atomic_generation() {
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
    let temp = tempfile::tempdir().unwrap();
    let (owner, group) = account_names();
    let value = json!({"testhost": {
        "metadata": {"socketPath": "/run/nix-secrets/backend.sock",
            "deployment": {"host": "testhost", "destination": "secrets@testhost", "port": 22}},
        "services": {"backup": {"storage-key": {
            "kind": "generated", "recipientPublicKeys": [KEY], "recipientIds": ["key"],
            "consumerUnits": ["backup.service"],
            "generatedSecret": {
                "type": "storage-box-ssh-key",
                "output": {"path": "/persistent/secrets/backup/backup/storage-key",
                    "category": "backup", "owner": owner, "group": group, "mode": "0400"},
                "bootstrap": {"host": "box.example", "port": 23, "user": "u1",
                    "hostPublicKeys": [KEY]}
            }
        }}}}
    });
    let path = temp.path().join("generated.json");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let state = load_target_state(&path, "testhost", &Default::default()).unwrap();
    assert!(state.secrets.is_empty());
    assert_eq!(state.tasks.len(), 1);
    assert_eq!(state.tasks[0].bootstrap.port, 23);
    assert_eq!(state.tasks[0].output.mode, "0400");

    let identifier = "testhost.services.backup.storage-key";
    let batch = DeploymentBatch {
        version: 1,
        requested_identifiers: vec![identifier.into()],
        entries: vec![request(identifier, b"OPENSSH-PRIVATE-KEY")],
    };
    let resolved = load_and_validate_manifest(&path, "testhost", &batch).unwrap();
    let root = temp.path().join("secrets");
    let deployer = Deployer::at(&root).unwrap();
    deployer.deploy(&resolved).unwrap();
    assert_eq!(
        fs::read(root.join("backup/backup/storage-key")).unwrap(),
        b"OPENSSH-PRIVATE-KEY"
    );
    let state = load_target_state(&path, "testhost", &deployer.current_versions().unwrap()).unwrap();
    assert_eq!(state.tasks[0].current_version_id.as_deref(), Some("version-one"));
}
