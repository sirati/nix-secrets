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
        public_info: None,
        current_version_id: None,
        generator: None,
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
        bootstrap: Some(StorageBoxBootstrap {
            host: "box.example".into(),
            port: 23,
            user: "u1".into(),
            host_public_keys: vec!["ssh-ed25519 AAAA".into()],
            known_hosts_file: None,
        }),
        current_version_id: version.map(str::to_owned),
    }
}
fn state(secret_ids: &[&str], tasks: Vec<TargetTask>) -> TargetState {
    TargetState {
        protocol_version: DEPLOYMENT_PROTOCOL_VERSION,
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
                public_info: None,
                generator: None,
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
    substituted.bootstrap.as_mut().unwrap().host = "attacker.example".into();
    assert!(validate_target(&state(&[], vec![substituted]), &expected).is_err());
}

#[test]
fn task_contribution_is_exactly_32_bytes() {
    let id = "host.services.backup.bootstrap";
    let target = state(&[], vec![task(id, None)]);
    for invalid in [vec![0; 31], vec![0; 33]] {
        let batch = DeploymentBatch {
            version: DEPLOYMENT_PROTOCOL_VERSION,
            requested_identifiers: vec![],
            entries: vec![],
            requested_tasks: vec![id.into()],
            tasks: vec![task_entry(id, "v1", &invalid)],
            generate: vec![],
        };
        assert!(validate_batch(&batch, &target).is_err());
    }
    let valid = DeploymentBatch {
        version: DEPLOYMENT_PROTOCOL_VERSION,
        requested_identifiers: vec![],
        entries: vec![],
        requested_tasks: vec![id.into()],
        tasks: vec![task_entry(id, "v1", &[7; 32])],
        generate: vec![],
    };
    assert!(validate_batch(&valid, &target).is_ok());
}

#[test]
fn local_key_task_requires_no_bootstrap_password() {
    let id = "host.services.mail.ssh-key";
    let mut local = task(id, None);
    local.task_type = LOCAL_SSH_KEY.into();
    local.output.path = "/persistent/secrets/mail/service/ssh-key".into();
    local.output.category = "service".into();
    local.bootstrap = None;
    let target = state(&[], vec![local]);
    let mut entry = task_entry(id, "local-generated-v1", &[7; 32]);
    entry.password_base64.clear();
    let mut batch = DeploymentBatch {
        version: DEPLOYMENT_PROTOCOL_VERSION,
        requested_identifiers: vec![],
        entries: vec![],
        requested_tasks: vec![id.into()],
        tasks: vec![entry],
        generate: vec![],
    };
    assert!(validate_batch(&batch, &target).is_ok());
    batch.tasks[0].password_base64 = STANDARD.encode(b"forbidden");
    assert!(validate_batch(&batch, &target).is_err());
}

#[test]
fn retry_of_current_version_is_accepted_but_selection_cannot_be_substituted() {
    let id = "host.services.backup.bootstrap";
    let target = state(&[], vec![task(id, Some("v1"))]);
    let retry = DeploymentBatch {
        version: DEPLOYMENT_PROTOCOL_VERSION,
        requested_identifiers: vec![],
        entries: vec![],
        requested_tasks: vec![id.into()],
        tasks: vec![task_entry(id, "v1", &[9; 32])],
        generate: vec![],
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
        version: DEPLOYMENT_PROTOCOL_VERSION,
        requested_identifiers: vec![],
        entries: vec![],
        requested_tasks: vec![id.into()],
        tasks: vec![task_entry(id, "v1", &[3; 32])],
        generate: vec![],
    };
    let mut input = Vec::new();
    write_wire_json(&mut input, &selection).unwrap();
    write_wire_json(&mut input, &batch).unwrap();
    let mut output = Vec::new();
    serve_deployment(input.as_slice(), &mut output, target.clone(), |_| {
        Ok(AppliedOutput {
            versions: BTreeMap::from([(id.into(), "v1".into())]),
            ..Default::default()
        })
    })
    .unwrap();
    let mut cursor = output.as_slice();
    assert_eq!(read_wire_json::<TargetState>(&mut cursor).unwrap(), target);
    assert!(matches!(
        read_wire_json::<DeploymentResult>(&mut cursor).unwrap(),
        DeploymentResult::Applied { .. }
    ));
}

fn generatable(identifier: &str) -> TargetSecret {
    let mut secret = target_secret(identifier);
    secret.generator = Some(r#"{"kind":"password"}"#.into());
    secret
}

fn generation_batch(entries: Vec<DeployEntry>, generate: &[&str]) -> DeploymentBatch {
    DeploymentBatch {
        version: DEPLOYMENT_PROTOCOL_VERSION,
        requested_identifiers: entries
            .iter()
            .map(|item| item.identifier.clone())
            .chain(generate.iter().map(|id| id.to_string()))
            .collect(),
        entries,
        requested_tasks: vec![],
        tasks: vec![],
        generate: generate
            .iter()
            .map(|id| GenerateEntry {
                identifier: (*id).into(),
                client_contribution_base64: STANDARD.encode([1_u8; 32]),
            })
            .collect(),
    }
}

#[test]
fn generation_is_limited_to_values_the_target_declares_generatable() {
    let fixed = "host.services.mail.fixed";
    let generated = "host.services.mail.generated";
    let target = TargetState {
        protocol_version: DEPLOYMENT_PROTOCOL_VERSION,
        hostname: "host".into(),
        secrets: vec![target_secret(fixed), generatable(generated)],
        tasks: vec![],
    };
    let supplied = DeployEntry {
        identifier: fixed.into(),
        version_id: "v1".into(),
        contents_base64: STANDARD.encode(b"x"),
    };
    assert!(validate_batch(
        &generation_batch(vec![supplied.clone()], &[generated]),
        &target
    )
    .is_ok());
    // A value without a target generator must be supplied.
    assert!(validate_batch(&generation_batch(vec![], &[fixed, generated]), &target).is_err());
    // A value cannot be both supplied and generated.
    let mut both = supplied.clone();
    both.identifier = generated.into();
    assert!(validate_batch(&generation_batch(vec![both], &[generated]), &target).is_err());
    // Protocol 1 targets cannot generate.
    let mut legacy = target.clone();
    legacy.protocol_version = LEGACY_DEPLOYMENT_PROTOCOL_VERSION;
    let mut batch = generation_batch(vec![supplied], &[generated]);
    batch.version = LEGACY_DEPLOYMENT_PROTOCOL_VERSION;
    assert!(validate_batch(&batch, &legacy).is_err());
}

#[test]
fn generator_descriptions_must_agree_before_generation() {
    let id = "host.services.mail.generated";
    let target = TargetState {
        protocol_version: DEPLOYMENT_PROTOCOL_VERSION,
        hostname: "host".into(),
        secrets: vec![generatable(id)],
        tasks: vec![],
    };
    let ids = [id.to_string()];
    let mut expected = expected(&[id], &[]);
    // Set values still deploy whatever the target would generate.
    assert!(validate_target(&target, &expected).is_ok());
    assert!(verify_generators(&target, &expected, &ids).is_err());
    expected.secrets[0].generator = Some(r#"{"kind":"password","constraints":{}}"#.into());
    assert!(verify_generators(&target, &expected, &ids).is_err());
    expected.secrets[0].generator = Some(r#"{"kind":"password"}"#.into());
    assert!(verify_generators(&target, &expected, &ids).is_ok());
    let mut older = target;
    older.secrets[0].generator = None;
    assert!(validate_target(&older, &expected).is_ok());
    assert!(verify_generators(&older, &expected, &ids).is_err());
}

#[test]
fn server_rejects_an_apply_that_omits_generated_records() {
    let id = "host.services.mail.generated";
    let target = TargetState {
        protocol_version: DEPLOYMENT_PROTOCOL_VERSION,
        hostname: "host".into(),
        secrets: vec![generatable(id)],
        tasks: vec![],
    };
    let run = |records: BTreeMap<String, GeneratedRecord>| {
        let mut input = Vec::new();
        write_wire_json(
            &mut input,
            &DeploymentSelection {
                identifiers: vec![id.into()],
                task_identifiers: vec![],
            },
        )
        .unwrap();
        write_wire_json(&mut input, &generation_batch(vec![], &[id])).unwrap();
        let mut output = Vec::new();
        serve_deployment(input.as_slice(), &mut output, target.clone(), |batch| {
            assert_eq!(batch.generate.len(), 1);
            Ok(AppliedOutput {
                generated_records: records,
                ..Default::default()
            })
        })
        .unwrap();
        let mut cursor = output.as_slice();
        read_wire_json::<TargetState>(&mut cursor).unwrap();
        read_wire_json::<DeploymentResult>(&mut cursor).unwrap()
    };
    assert!(matches!(
        run(BTreeMap::new()),
        DeploymentResult::Rejected { .. }
    ));
    let record = GeneratedRecord {
        format_version: 1,
        version_id_base64: STANDARD.encode([0_u8; 16]),
        recipient_ids: vec!["key".into()],
        age_ciphertext_base64: STANDARD.encode(b"age"),
        adopted: false,
    };
    assert!(matches!(
        run(BTreeMap::from([(id.to_string(), record)])),
        DeploymentResult::Applied { generated_records, .. } if generated_records.len() == 1
    ));
}
