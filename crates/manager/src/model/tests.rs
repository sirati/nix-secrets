use super::*;
fn leaf(set: bool) -> Row {
    Row {
        depth: 0,
        name: "key".into(),
        display_segments: vec![],
        path: Some("h.services.s.key".into()),
        is_set: set,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Other,
        human_facing: false,
        external_input_required: true,
        required_for_install: false,
        identity: None,
        presentation: None,
    }
}

#[test]
fn replacing_a_set_leaf_opens_entry_first() {
    let mut model = Model::new(vec![leaf(true)]);
    model.begin_value(b"new".to_vec());
    assert!(
        matches!(model.mode, Mode::Edit { .. }),
        "confirmation waits for Enter"
    );
    assert!(model.is_set("h.services.s.key"));
}

#[test]
fn unset_leaf_enters_editor_directly() {
    let mut model = Model::new(vec![leaf(false)]);
    model.begin_value(Vec::new());
    assert!(matches!(model.mode, Mode::Edit { .. }));
}

#[test]
fn notices_are_acknowledged_in_order_before_pending_approval() {
    let mut model = Model::new(vec![]);
    model.fail("first");
    model.inform("second");
    model.offer_approval(ApprovalRequest {
        id: "id".into(),
        target: "host".into(),
        create: vec![],
        replace: vec![],
        recipient_keys: vec![],
        host_key: None,
        tasks: vec![],
        generate: vec![],
        missing: vec![],
        derived: vec![],
    });
    assert!(matches!(model.mode, Mode::Browse));
    assert_eq!(model.message_text(), Some("first"));
    model.acknowledge();
    assert_eq!(model.message_text(), Some("second"));
    model.acknowledge();
    assert!(matches!(model.mode, Mode::Approval(_)));
}
