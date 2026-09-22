use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeMap;

fn destination() -> Destination {
    Destination {
        path: "/persistent/secrets/mail/service/password".into(),
        category: "service".into(),
        owner: "mail".into(),
        group: "mail".into(),
        mode: "0400".into(),
        consumer_units: vec!["mail.service".into()],
    }
}
fn target_secret(identifier: &str) -> TargetSecret {
    TargetSecret {
        identifier: identifier.into(),
        recipient_ids: vec!["key".into()],
        destination: destination(),
        current_version_id: None,
    }
}
fn task(identifier: &str, version: Option<&str>) -> TargetTask {
    let mut output = destination();
    output.path = "/persistent/secrets/backup/backup/storage-box-key".into();
    output.category = "backup".into();
    TargetTask {
        identifier: identifier.into(),
        task_type: STORAGE_BOX_SSH_KEY.into(),
        recipient_ids: vec!["operator".into()],
        output,
        bootstrap: StorageBoxBootstrap {
            host: "box.example".into(),
            port: 23,
            user: "u1".into(),
            host_public_keys: vec!["ssh-ed25519 AAAA".into()],
        },
        current_version_id: version.map(str::to_owned),
    }
}
fn state(secret_ids: &[&str], tasks: Vec<TargetTask>) -> TargetState {
    TargetState {
        protocol_version: 1,
        hostname: "host".into(),
        secrets: secret_ids.iter().map(|id| target_secret(id)).collect(),
        tasks,
    }
}
fn expected(secret_ids: &[&str], tasks: &[TargetTask]) -> ExpectedTarget {
    ExpectedTarget {
        hostname: "host".into(),
        secrets: secret_ids
            .iter()
            .map(|id| ExpectedSecret {
                identifier: (*id).into(),
                recipient_ids: vec!["key".into()],
                destination: destination(),
            })
            .collect(),
        tasks: tasks
            .iter()
            .map(|item| ExpectedTask {
                identifier: item.identifier.clone(),
                task_type: item.task_type.clone(),
                recipient_ids: item.recipient_ids.clone(),
                output: item.output.clone(),
                bootstrap: item.bootstrap.clone(),
            })
            .collect(),
    }
}
fn task_entry(id: &str, version: &str, contribution: &[u8]) -> TaskEntry {
    TaskEntry {
        identifier: id.into(),
        version_id: version.into(),
        password_base64: STANDARD.encode(b"pw"),
        client_contribution_base64: STANDARD.encode(contribution),
    }
}

#[test]
fn target_validation_rejects_task_substitution() {
    let actual_task = task("host.services.backup.bootstrap", None);
    let expected = expected(&[], std::slice::from_ref(&actual_task));
    assert!(validate_target(&state(&[], vec![actual_task.clone()]), &expected).is_ok());
    let mut substituted = actual_task;
    substituted.bootstrap.host = "attacker.example".into();
    assert!(validate_target(&state(&[], vec![substituted]), &expected).is_err());
}

#[test]
fn task_contribution_is_exactly_32_bytes() {
    let id = "host.services.backup.bootstrap";
    let target = state(&[], vec![task(id, None)]);
    for invalid in [vec![0; 31], vec![0; 33]] {
        let batch = DeploymentBatch {
            version: 1,
            requested_identifiers: vec![],
            entries: vec![],
            requested_tasks: vec![id.into()],
            tasks: vec![task_entry(id, "v1", &invalid)],
        };
        assert!(validate_batch(&batch, &target).is_err());
    }
    let valid = DeploymentBatch {
        version: 1,
        requested_identifiers: vec![],
        entries: vec![],
        requested_tasks: vec![id.into()],
        tasks: vec![task_entry(id, "v1", &[7; 32])],
    };
    assert!(validate_batch(&valid, &target).is_ok());
}

#[test]
fn retry_of_current_version_is_accepted_but_selection_cannot_be_substituted() {
    let id = "host.services.backup.bootstrap";
    let target = state(&[], vec![task(id, Some("v1"))]);
    let retry = DeploymentBatch {
        version: 1,
        requested_identifiers: vec![],
        entries: vec![],
        requested_tasks: vec![id.into()],
        tasks: vec![task_entry(id, "v1", &[9; 32])],
    };
    assert!(validate_batch(&retry, &target).is_ok());
    let mut substituted = retry;
    substituted.tasks[0].identifier = "host.services.backup.other".into();
    assert!(validate_batch(&substituted, &target).is_err());
}

#[test]
fn bounded_wire_json_round_trips_and_rejects_oversize_header() {
    let original = state(&["host.services.mail.password"], vec![]);
    let mut bytes = Vec::new();
    write_wire_json(&mut bytes, &original).unwrap();
    assert_eq!(
        read_wire_json::<TargetState>(&mut bytes.as_slice()).unwrap(),
        original
    );
    let oversized = ((MAX_DEPLOYMENT_JSON as u32) + 1).to_be_bytes();
    assert!(matches!(
        read_wire_json::<TargetState>(&mut oversized.as_slice()),
        Err(DeploymentError::Invalid(_))
    ));
}

#[test]
fn server_sends_selected_task_then_applies_exact_batch() {
    let id = "host.services.backup.bootstrap";
    let target = state(&[], vec![task(id, None)]);
    let selection = DeploymentSelection {
        identifiers: vec![],
        task_identifiers: vec![id.into()],
    };
    let batch = DeploymentBatch {
        version: 1,
        requested_identifiers: vec![],
        entries: vec![],
        requested_tasks: vec![id.into()],
        tasks: vec![task_entry(id, "v1", &[3; 32])],
    };
    let mut input = Vec::new();
    write_wire_json(&mut input, &selection).unwrap();
    write_wire_json(&mut input, &batch).unwrap();
    let mut output = Vec::new();
    serve_deployment(input.as_slice(), &mut output, target.clone(), |_| {
        Ok(BTreeMap::from([(id.into(), "v1".into())]))
    })
    .unwrap();
    let mut cursor = output.as_slice();
    assert_eq!(read_wire_json::<TargetState>(&mut cursor).unwrap(), target);
    assert!(matches!(
        read_wire_json::<DeploymentResult>(&mut cursor).unwrap(),
        DeploymentResult::Applied { .. }
    ));
}
