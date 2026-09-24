use super::*;

#[test]
fn builds_sorted_tree_and_marks_set_leaves() {
    let schema = Schema::from_json(r#"{"host":{"metadata":{"socketPath":"/run/s","deployment":{"host":"host","destination":"nix-secrets-forward@host","port":22}},"services":{"mail":{"password":{"kind":"secret","recipientPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"],"recipientIds":["key"],"destination":{"path":"/persistent/secrets/mail/service/password","category":"service","owner":"mail","group":"mail","mode":"0400"},"consumerUnits":[]}}}}}"#).unwrap();
    let set = BTreeSet::from(["host.services.mail.password".into()]);
    let rows = rows(&schema, &set);
    assert_eq!(
        rows.last().unwrap(),
        &Row {
            depth: 3,
            name: "password".into(),
            display_segments: vec![
                "host".into(),
                "services".into(),
                "mail".into(),
                "password".into()
            ],
            path: Some("host.services.mail.password".into()),
            is_set: true,
            is_task: false,
            can_generate: false,
            can_copy_public: false,
            output_is_set: None,
            description: None,
            category: RowCategory::Other,
            human_facing: false,
            external_input_required: false,
        }
    );
}

#[test]
fn generated_leaf_is_a_task_with_separate_output_status() {
    let schema = Schema::from_json(r#"{"host":{"metadata":{"socketPath":"/run/s","deployment":{"host":"host","destination":"nix-secrets-forward@host","port":22}},"services":{"backup":{"bootstrap":{"kind":"generated","recipientPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"],"recipientIds":["key"],"consumerUnits":[],"generatedSecret":{"type":"storage-box-ssh-key","output":{"path":"/persistent/secrets/backup/backup/key","category":"backup","owner":"backup","group":"backup","mode":"0400"},"bootstrap":{"host":"box","port":23,"user":"u","hostPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"]}}}}}}}"#).unwrap();
    let set = BTreeSet::from(["host.services.backup.bootstrap".into()]);
    let row = rows(&schema, &set).pop().unwrap();
    assert!(row.is_task());
    assert!(row.is_set);
    assert_eq!(row.output_is_set, None);
}

#[test]
fn target_generated_local_key_is_not_an_editable_row() {
    let mut schema: serde_json::Value = serde_json::from_str(r#"{"host":{"metadata":{"socketPath":"/run/s","deployment":{"host":"host","destination":"secrets@host","port":22}},"services":{"mail":{"ssh-private-key":{"kind":"generated","recipientPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"],"recipientIds":["key"],"consumerUnits":[],"generatedSecret":{"type":"local-ssh-key","output":{"path":"/persistent/secrets/mail/service/ssh-private-key","category":"service","owner":"mail","group":"mail","mode":"0400","contentType":"openssh-private-key"}}}}}}}"#).unwrap();
    schema["host"]["services"]["mail"]["ssh-private-key"]["description"] =
        "Generated on target".into();
    let schema = Schema::from_json(&schema.to_string()).unwrap();
    assert!(rows(&schema, &BTreeSet::new())
        .iter()
        .all(|row| row.path.is_none()));
}

#[test]
fn display_paths_group_independent_services_without_changing_identifiers() {
    let mut value: serde_json::Value = serde_json::from_str(r#"{"host":{"metadata":{"socketPath":"/run/s","deployment":{"host":"host","destination":"secrets@host","port":22}},"services":{"forgejo":{"token":{"kind":"secret","recipientPublicKeys":["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin"],"recipientIds":["key"],"destination":{"path":"/persistent/secrets/forgejo/service/token","category":"service","owner":"git","group":"git","mode":"0400"},"consumerUnits":[]}}}}}"#).unwrap();
    let mut backup = value["host"]["services"]["forgejo"].clone();
    backup["token"]["destination"]["path"] =
        "/persistent/secrets/backup-forgejo/service/token".into();
    value["host"]["services"]["backup-forgejo"] = backup;
    value["host"]["metadata"]["serviceDisplayPaths"] = serde_json::json!({
        "services": {
            "forgejo": ["forgejo", "service"],
            "backup-forgejo": ["forgejo", "backup"]
        }
    });
    let schema = Schema::from_json(&value.to_string()).unwrap();
    let mut model = crate::model::Model::new(rows(&schema, &BTreeSet::new()));
    model.set_filter(crate::model::ViewFilter::All);
    let visible = model.visible_tree_rows();
    assert!(visible.iter().any(|row| row.label == "forgejo"));
    assert!(visible.iter().any(|row| row.label == "backup/token"));
    assert!(visible.iter().any(|row| row.label == "service/token"));
    let paths = visible
        .iter()
        .filter_map(|row| model.rows[row.index].path.as_deref())
        .collect::<Vec<_>>();
    assert!(paths.contains(&"host.services.backup-forgejo.token"));
    assert!(paths.contains(&"host.services.forgejo.token"));
}

#[test]
fn required_view_uses_external_anchor_flag_not_password_or_generator_kind() {
    let key =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
    let schema = serde_json::json!({
        "host": {
            "metadata": {"socketPath":"/run/s", "deployment":{"host":"host","destination":"secrets@host","port":22}},
            "services": {"backup": {
                "borg-passphrase": {
                    "kind":"secret", "valueType":"password", "recipientPublicKeys":[key], "recipientIds":["key"], "consumerUnits":[],
                    "destination":{"path":"/persistent/secrets/backup/backup/borg-passphrase","category":"backup","owner":"backup","group":"backup","mode":"0400"}
                },
                "storagebox-access": {
                    "kind":"generated", "valueType":"password", "externalInputRequired":true,
                    "recipientPublicKeys":[key], "recipientIds":["key"], "consumerUnits":[],
                    "generatedSecret":{"type":"storage-box-ssh-key","output":{"path":"/persistent/secrets/backup/backup/ssh-key","category":"backup","owner":"backup","group":"backup","mode":"0400"},"bootstrap":{"host":"box","port":23,"user":"u","hostPublicKeys":[key]}}
                }
            }}
        }
    });
    let schema = Schema::from_json(&schema.to_string()).unwrap();
    let rows = rows(&schema, &BTreeSet::new());
    assert!(rows.iter().any(|row| row.name == "borg-passphrase"
        && row.can_generate
        && !row.external_input_required));
    assert!(rows.iter().any(|row| row.name == "storagebox-access"
        && row.can_generate
        && row.external_input_required));
    let model = crate::model::Model::new(rows);
    let required = model
        .visible_rows()
        .into_iter()
        .filter_map(|index| model.rows[index].path.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(required, ["host.services.backup.storagebox-access"]);
}
