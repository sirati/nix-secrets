use super::*;

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
fn expected_secret(identifier: &str) -> ExpectedSecret {
    ExpectedSecret {
        identifier: identifier.into(),
        recipient_ids: vec!["key".into()],
        destination: destination(),
    }
}
fn state(ids: &[&str]) -> TargetState {
    TargetState {
        protocol_version: 1,
        hostname: "host".into(),
        secrets: ids.iter().map(|id| target_secret(id)).collect(),
    }
}
fn expected(ids: &[&str]) -> ExpectedTarget {
    ExpectedTarget {
        hostname: "host".into(),
        secrets: ids.iter().map(|id| expected_secret(id)).collect(),
    }
}

#[test]
fn target_validation_rejects_mismatch_omission_and_extra() {
    assert!(validate_target(
        &state(&["host.services.mail.password"]),
        &expected(&["host.services.mail.password"])
    )
    .is_ok());
    assert!(validate_target(
        &state(&["host.services.mail.other"]),
        &expected(&["host.services.mail.password"])
    )
    .is_err());
    assert!(validate_target(&state(&[]), &expected(&["host.services.mail.password"])).is_err());
    assert!(validate_target(
        &state(&["host.services.mail.password", "host.services.mail.extra"]),
        &expected(&["host.services.mail.password"])
    )
    .is_err());
    let mut wrong_host = expected(&["host.services.mail.password"]);
    wrong_host.hostname = "other".into();
    assert!(validate_target(&state(&["host.services.mail.password"]), &wrong_host).is_err());
}

#[test]
fn deployment_batch_must_be_complete_and_unique() {
    let secrets = state(&["host.services.mail.password", "host.services.mail.token"]).secrets;
    let entry = |id: &str| DeployEntry {
        identifier: id.into(),
        version_id: "opaque".into(),
        contents_base64: "c2VjcmV0".into(),
    };
    let requested = vec!["host.services.mail.password".into()];
    assert!(validate_entries(
        &[entry("host.services.mail.password")],
        &requested,
        &secrets
    )
    .is_ok());
    assert!(validate_entries(
        &[
            entry("host.services.mail.password"),
            entry("host.services.mail.token")
        ],
        &requested,
        &secrets
    )
    .is_err());
    assert!(validate_entries(&[], &requested, &secrets).is_err());
    assert!(validate_entries(
        &[
            entry("host.services.mail.password"),
            entry("host.services.mail.password")
        ],
        &requested,
        &secrets
    )
    .is_err());
    assert!(validate_entries(
        &[entry("host.services.mail.unknown")],
        &["host.services.mail.unknown".into()],
        &secrets
    )
    .is_err());
}

#[test]
fn bounded_wire_json_round_trips_and_rejects_oversize_header() {
    let original = state(&["host.services.mail.password"]);
    let mut bytes = Vec::new();
    write_wire_json(&mut bytes, &original).unwrap();
    let decoded: TargetState = read_wire_json(&mut bytes.as_slice()).unwrap();
    assert_eq!(decoded, original);
    let oversized = ((MAX_DEPLOYMENT_JSON as u32) + 1).to_be_bytes();
    assert!(matches!(
        read_wire_json::<TargetState>(&mut oversized.as_slice()),
        Err(DeploymentError::Invalid(_))
    ));
}

#[test]
fn server_sends_state_then_applies_exact_batch() {
    let target = state(&["host.services.mail.password"]);
    let batch = DeploymentBatch {
        version: 1,
        requested_identifiers: vec!["host.services.mail.password".into()],
        entries: vec![DeployEntry {
            identifier: "host.services.mail.password".into(),
            version_id: "v1".into(),
            contents_base64: "cw==".into(),
        }],
    };
    let selection = DeploymentSelection {
        identifiers: vec!["host.services.mail.password".into()],
    };
    let mut input = Vec::new();
    write_wire_json(&mut input, &selection).unwrap();
    write_wire_json(&mut input, &batch).unwrap();
    let mut output = Vec::new();
    serve_deployment(input.as_slice(), &mut output, target.clone(), |_| {
        Ok(BTreeMap::from([(
            "host.services.mail.password".into(),
            "v1".into(),
        )]))
    })
    .unwrap();
    let mut cursor = output.as_slice();
    assert_eq!(read_wire_json::<TargetState>(&mut cursor).unwrap(), target);
    assert!(matches!(
        read_wire_json::<DeploymentResult>(&mut cursor).unwrap(),
        DeploymentResult::Applied { .. }
    ));
}

#[test]
fn server_selection_allows_subset_but_rejects_unknown_and_duplicates() {
    let full = state(&["host.services.mail.password", "host.services.mail.future"]);
    let selected = select_state(&full, &["host.services.mail.password".into()]).unwrap();
    assert_eq!(selected.secrets.len(), 1);
    assert!(select_state(&full, &["host.services.mail.unknown".into()]).is_err());
    assert!(select_state(
        &full,
        &[
            "host.services.mail.password".into(),
            "host.services.mail.password".into()
        ]
    )
    .is_err());
}
