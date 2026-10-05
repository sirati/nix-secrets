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
fn approval_suspends_failure_without_acknowledging_or_discarding_notices() {
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
        skippable: vec![],
        missing_kinds: Default::default(),
        host_default: vec![],
        allow_partial: false,
        ..Default::default()
    });
    assert!(model.message.is_none());
    assert!(matches!(model.mode, Mode::Approval(_)));
    model.mode = Mode::Browse;
    model.show_pending_approval();
    assert_eq!(model.message_text(), Some("first"));
    model.acknowledge();
    assert_eq!(model.message_text(), Some("second"));
}

#[test]
fn completed_exact_request_never_reappears_after_return_to_browse() {
    let mut model=Model::new(vec![]);
    let request=ApprovalRequest{id:"pubkey-completed".into(),target:"ns1".into(),create:vec!["ns1.services.report-authorized.updatealert".into()],..Default::default()};
    model.offer_approval(request.clone());
    assert!(matches!(&model.mode,Mode::Approval(current) if current.id==request.id));
    model.finish_approval(&request.id);
    assert!(matches!(model.mode,Mode::Browse));
    model.offer_approval(request.clone());
    model.show_pending_approval();
    assert!(matches!(model.mode,Mode::Browse));
    assert!(model.pending_approvals.is_empty());
    let another=ApprovalRequest{id:"pubkey-new".into(),..request};
    model.offer_approval(another.clone());
    assert!(matches!(&model.mode,Mode::Approval(current) if current.id==another.id));
}
#[test]
fn trust_to_final_same_id_advances_and_stale_trust_cannot_rewind_it() {
    let mut model=Model::new(vec![]);
    let trust=ApprovalRequest{id:"same".into(),host_key:Some("verified public key".into()),..Default::default()};
    model.offer_approval(trust.clone());
    let final_stage=ApprovalRequest{host_key:None,..trust.clone()};
    model.offer_approval(final_stage.clone());
    assert!(matches!(&model.mode,Mode::Approval(current) if current.host_key.is_none()));
    model.offer_approval(trust);
    assert!(matches!(&model.mode,Mode::Approval(current) if current.host_key.is_none()));
    assert!(model.pending_approvals.is_empty());
    model.finish_approval("same");
    model.offer_approval(final_stage);
    assert!(matches!(model.mode,Mode::Browse));
}
#[test]
fn terminal_result_removes_queued_copy_while_another_dialog_stays_active() {
    let mut model=Model::new(vec![]);
    model.offer_approval(ApprovalRequest{id:"other".into(),..Default::default()});
    let queued=ApprovalRequest{id:"finished".into(),..Default::default()};
    model.offer_approval(queued.clone());model.offer_approval(queued.clone());
    assert_eq!(model.pending_approvals.len(),1);
    model.finish_approval("finished");
    assert!(matches!(&model.mode,Mode::Approval(current) if current.id=="other"));
    model.offer_approval(queued);
    assert!(model.pending_approvals.is_empty());
}

#[test]
fn host_mutation_review_advances_same_request_and_stale_deploy_cannot_replace_it() {
    let normal = ApprovalRequest {
        id: "host-return".into(),
        target: "producer".into(),
        ..Default::default()
    };
    let mut review = normal.clone();
    review.host_mutation_token = Some("exact-batch".into());
    review.host_mutations.push(HostMutationReview {
        identifier: "receiver.services.report.known-hosts".into(),
        kind: "report receiver host identity".into(),
        previous: vec!["SHA256:old".into()],
        proposed: vec!["SHA256:new".into()],
    });
    let mut model = Model::new(vec![]);
    model.offer_approval(normal.clone());
    model.offer_approval(review.clone());
    model.offer_approval(normal.clone());
    assert!(
        matches!(&model.mode,Mode::Approval(current) if current.host_mutation_token.as_deref()==Some("exact-batch"))
    );
    let mut deferred = Model::new(vec![]);
    deferred.mode = Mode::Edit {
        path: "unrelated".into(),
        value: Zeroizing::new(vec![]),
    };
    deferred.offer_approval(review.clone());
    deferred.offer_approval(normal);
    assert_eq!(deferred.pending_approvals.len(), 1);
    assert_eq!(
        deferred.pending_approvals[0].host_mutation_token.as_deref(),
        Some("exact-batch")
    );
    model.finish_approval("host-return");
    model.offer_approval(review);
    assert!(matches!(model.mode, Mode::Browse));
}
