use super::*;
fn leaf(set: bool) -> Row {
    Row {
        depth: 0,
        name: "key".into(),
        path: Some("h.services.s.key".into()),
        is_set: set,
        is_task: false,
        can_generate: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Other,
        human_facing: false,
    }
}

#[test]
fn replacing_a_set_leaf_requires_confirmation() {
    let mut model = Model::new(vec![leaf(true)]);
    model.begin_value(b"new".to_vec());
    assert!(matches!(model.mode, Mode::Replace { .. }));
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
    model.notify("first");
    model.notify("second");
    model.offer_approval(ApprovalRequest {
        id: "id".into(),
        target: "host".into(),
        create: vec![],
        replace: vec![],
        recipient_keys: vec![],
        host_key: None,
        tasks: vec![],
    });
    assert!(matches!(model.mode, Mode::Browse));
    assert_eq!(model.message.as_deref(), Some("first"));
    model.acknowledge();
    assert_eq!(model.message.as_deref(), Some("second"));
    model.acknowledge();
    assert!(matches!(model.mode, Mode::Approval(_)));
}
