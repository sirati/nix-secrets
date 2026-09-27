//! The ns1 case and its relatives, decided before connecting.
use super::*;
use serde_json::json;

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
const FILE: &str = "/persistent/public-info/storage-box/known-hosts";

fn schema(public: serde_json::Value, protocol: Option<u16>, known_hosts_file: &str) -> Schema {
    let mut deployment = json!({"host": "ns1", "destination": "nix-secrets-forward@ns1", "port": 22});
    if let Some(version) = protocol {
        deployment["protocolVersion"] = json!(version);
    }
    let mut known_hosts = json!({
        "kind": "public-info", "sharedPublicId": "storage-box/known-hosts",
        "expectedSshHost": "u1.box.example", "expectedSshHosts": ["u1-sub17.box.example"],
        "expectedSshPort": 23, "installDefaultIfMissing": true, "consumerUnits": [],
        "destination": {"path": FILE, "category": "public-info", "owner": "root",
            "group": "root", "mode": "0644", "contentType": "ssh-known-hosts"}});
    known_hosts
        .as_object_mut()
        .unwrap()
        .extend(public.as_object().unwrap().clone());
    let document = json!({"ns1": {
        "metadata": {"socketPath": "/run/nix-secrets/backend.sock", "deployment": deployment},
        "services": {
            "backup-public-info": {"storage-box-known-hosts": known_hosts},
            "backup-dns-primary": {"storagebox-access": {
                "kind": "generated", "recipientPublicKeys": [KEY], "recipientIds": ["primary"],
                "consumerUnits": [], "valueType": "password",
                "generatedSecret": {"type": "storage-box-ssh-key",
                    "output": {"path": "/persistent/secrets/backup-dns-primary/backup/storagebox-access",
                        "category": "backup", "owner": "root", "group": "root", "mode": "0400"},
                    "bootstrap": {"host": "u1-sub17.box.example", "port": 23, "user": "u1-sub17",
                        "knownHostsFile": known_hosts_file}}}},
            "app": {"cookie": {
                "kind": "secret", "recipientPublicKeys": [KEY], "recipientIds": ["primary"],
                "consumerUnits": [], "valueType": "password",
                "destination": {"path": "/persistent/secrets/app/service/cookie",
                    "category": "service", "owner": "root", "group": "root", "mode": "0400"}}}
        }}});
    Schema::from_json(&document.to_string()).unwrap()
}

const PUBLIC: &str = "ns1.services.backup-public-info.storage-box-known-hosts";
const TASK: &str = "ns1.services.backup-dns-primary.storagebox-access";
const COOKIE: &str = "ns1.services.app.cookie";

fn plan(schema: &Schema, set: &[&str]) -> UnsetPlan {
    let identifiers = [PUBLIC, TASK, COOKIE].map(str::to_owned);
    let set = set.iter().map(|id| id.to_string()).collect();
    super::super::unset::plan_unset(schema, &identifiers, &set).unwrap()
}

fn reason<'a>(plan: &'a UnsetPlan, identifier: &str) -> Option<&'a str> {
    plan.missing
        .iter()
        .find(|(id, _)| id == identifier)
        .map(|(_, reason)| reason.as_str())
}

/// ns1: the known_hosts public information has no record and no default.
/// The Storage Box task is listed with the path before anything connects;
/// everything else still deploys.
#[test]
fn an_unset_known_hosts_without_default_is_listed_before_connecting() {
    let schema = schema(json!({}), Some(4), FILE);
    let plan = plan(&schema, &[TASK]);
    let why = reason(&plan, TASK).expect("the task is left out");
    assert!(why.contains(FILE) && why.contains("is absent"), "{why}");
    assert!(why.contains("defaultValue"), "{why}");
    assert_eq!(plan.reasons[TASK], MissingKind::CannotDeploy);
    assert!(plan.skippable.contains(&TASK.to_owned()));
    // The cookie is still generated on the target.
    assert!(plan.generate.iter().any(|(id, _)| id == COOKIE));
}

/// With a defaultValue in Nix the task deploys: the value is sent with it.
#[test]
fn a_default_value_provides_the_known_hosts_to_the_task() {
    let value = format!("[u1-sub17.box.example]:23 {KEY}\n");
    let schema = schema(json!({"defaultValue": value}), Some(4), FILE);
    // `plan_set` counts a leaf with a default as set.
    let plan = plan(&schema, &[TASK, PUBLIC]);
    assert_eq!(reason(&plan, TASK), None, "{plan:?}");
    assert!(!plan.host_default.contains(&PUBLIC.to_owned()));
}

/// A default that names only another sub-account gives this task no key.
#[test]
fn a_default_without_the_tasks_host_is_listed() {
    let value = format!("[u1.box.example]:23 {KEY}\n");
    let schema = schema(json!({"defaultValue": value}), Some(4), FILE);
    let plan = plan(&schema, &[TASK, PUBLIC]);
    let why = reason(&plan, TASK).unwrap();
    assert!(why.contains("holds no key for [u1-sub17.box.example]:23"), "{why}");
}

/// A knownHostsFile no public-info leaf declares is never provided.
#[test]
fn an_undeclared_known_hosts_file_is_listed() {
    let other = "/persistent/public-info/storage-box/other";
    let schema = schema(json!({}), Some(4), other);
    let plan = plan(&schema, &[TASK, PUBLIC]);
    let why = reason(&plan, TASK).unwrap();
    assert!(why.contains(other) && why.contains("is not public information of ns1"), "{why}");
}

/// A receiver too old for a feature: the value is listed, the rest deploys.
#[test]
fn a_receiver_too_old_for_generation_or_several_hosts_is_listed() {
    let value = format!("[u1-sub17.box.example]:23 {KEY}\n[u1.box.example]:23 {KEY}\n");
    let schema = schema(json!({"defaultValue": value}), Some(1), FILE);
    let plan = plan(&schema, &[TASK, PUBLIC]);
    let why = reason(&plan, COOKIE).unwrap();
    assert!(why.contains("deployment protocol 1") && why.contains("update the host"), "{why}");
    assert!(!plan.generate.iter().any(|(id, _)| id == COOKIE));
    let why = reason(&plan, PUBLIC).unwrap();
    assert!(why.contains("several hosts"), "{why}");
    // Unknown protocol: decided after connecting, as before.
    let schema = self::schema(json!({}), None, FILE);
    assert_eq!(reason(&self::plan(&schema, &[TASK]), COOKIE), None);
}
