use base64::{engine::general_purpose::STANDARD, Engine};
use nix::unistd::{getegid, geteuid, Group, User};
use nix_secrets_deploy::{load_target_state, run_generated_tasks};
use nix_secrets_transport::TaskEntry;
use serde_json::json;
use std::fs;

#[test]
fn local_key_stays_on_target_and_only_dated_public_key_is_returned() {
    let temp = tempfile::tempdir().unwrap();
    let owner = User::from_uid(geteuid()).unwrap().unwrap().name;
    let group = Group::from_gid(getegid()).unwrap().unwrap().name;
    let value = json!({"testhost": {
        "metadata": {"socketPath": "/run/nix-secrets/backend.sock",
            "deployment": {"host": "testhost", "destination": "secrets@testhost", "port": 22}},
        "services": {"mail": {"ssh-key": {
            "kind": "generated",
            "recipientPublicKeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"],
            "recipientIds": ["key"], "consumerUnits": ["mail.service"],
            "generatedSecret": {"type": "local-ssh-key",
                "output": {"path": "/persistent/secrets/mail/service/ssh-key",
                    "category": "service", "owner": owner, "group": group, "mode": "0400"},
                "registerAt": "other.services.authorized-keys.mail"}
        }}}}
    });
    let manifest = temp.path().join("manifest.json");
    fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    let state = load_target_state(&manifest, "testhost", &Default::default()).unwrap();
    assert_eq!(state.tasks[0].task_type, "local-ssh-key");
    assert!(state.tasks[0].bootstrap.is_none());
    let id = "testhost.services.mail.ssh-key";
    let generated = run_generated_tasks(
        &manifest,
        "testhost",
        &[TaskEntry {
            identifier: id.into(),
            version_id: "v1".into(),
            password_base64: String::new(),
            client_contribution_base64: STANDARD.encode([9; 32]),
        }],
    )
    .unwrap();
    assert_eq!(generated.deployments.len(), 1);
    let private = STANDARD
        .decode(&generated.deployments[0].contents_base64)
        .unwrap();
    assert!(private.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----"));
    let public = &generated.public_keys[id];
    assert!(public.contains(" ssh-ed25519 "));
    assert!(!public.contains("PRIVATE KEY"));
    assert!(!temp.path().join("ssh-key").exists());
}
