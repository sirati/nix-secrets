use super::*;

mod facets;
mod profiles;

#[test]
fn idle_ticks_do_not_redraw_the_terminal() {
    let mut frontend = FakeFrontend {
        events: VecDeque::from([UiEvent::Tick, UiEvent::Tick, UiEvent::Escape]),
        draws: 0,
    };
    drive(&mut frontend, &mut writer(), &mut model(false)).unwrap();
    assert_eq!(frontend.draws, 1);
}

#[test]
fn lost_lease_drops_the_modal_and_reports_expiry() {
    let mut frontend = FakeFrontend {
        events: VecDeque::from([UiEvent::Tick, UiEvent::Enter, UiEvent::Escape]),
        draws: 0,
    };
    let mut writer = writer();
    writer.poll_error = true;
    let mut model = model(true);
    model.mode = Mode::Approval(ApprovalRequest {
        id: "id".into(),
        target: "h".into(),
        create: vec![],
        replace: vec!["h.services.s.key".into()],
        recipient_keys: vec![],
        host_key: None,
        tasks: vec![],
    });
    drive(&mut frontend, &mut writer, &mut model).unwrap();
    assert!(matches!(model.mode, Mode::Browse));
    assert!(
        model.message.is_none(),
        "Enter acknowledged the lease-loss notice"
    );
}

#[test]
fn task_provider_failure_keeps_approval_for_retry() {
    let mut model = model(true);
    let mut writer = writer();
    let request = ApprovalRequest {
        id: "id".into(),
        target: "h".into(),
        create: vec![],
        replace: vec![],
        recipient_keys: vec!["operator".into()],
        host_key: None,
        tasks: vec![TaskApproval {
            identifier: "h.services.backup.bootstrap".into(),
            input_is_set: true,
            output_is_set: Some(false),
            requires_input: true,
        }],
    };
    model.mode = Mode::Approval(request);
    writer.approval_error = true;
    assert_eq!(
        reduce(&mut model, UiEvent::Character('y'), &mut writer),
        Action::Continue
    );
    assert!(matches!(model.mode, Mode::Approval(_)));
    writer.approval_error = false;
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert_eq!(
        reduce(&mut model, UiEvent::Character('y'), &mut writer),
        Action::Approved
    );
}

#[test]
fn deleting_a_set_leaf_requires_confirmation_and_never_requests_deployment() {
    let mut set = model(true);
    let mut writer = writer();
    reduce(&mut set, UiEvent::Character('d'), &mut writer);
    assert!(writer.deletions.is_empty());
    assert!(matches!(set.mode, Mode::DeleteConfirm { .. }));
    reduce(&mut set, UiEvent::Character('y'), &mut writer);
    assert_eq!(writer.deletions, ["h.services.s.key"]);

    let mut unset = model(false);
    reduce(&mut unset, UiEvent::Character('d'), &mut writer);
    assert_eq!(writer.deletions, ["h.services.s.key"]);
    assert_eq!(unset.message_text(), Some("select a set secret to delete"));
}

#[test]
fn reveal_is_explicit_and_hidden_on_escape() {
    let mut model = model(true);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('r'), &mut writer);
    assert!(matches!(model.mode, Mode::Reveal { .. }));
    assert!(!format!("{:?}", model.mode).contains("stored-value"));
    reduce(&mut model, UiEvent::Escape, &mut writer);
    assert!(matches!(model.mode, Mode::Browse));
}

#[test]
fn filters_use_explicit_value_categories() {
    let mut model = model(true);
    model.rows.push(Row {
        depth: 0,
        name: "certificate".into(),
        display_segments: vec![],
        path: Some("h.services.s.certificate".into()),
        is_set: true,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: Some("TLS certificate chain".into()),
        category: RowCategory::Other,
        human_facing: false,
        external_input_required: true,
        identity: None,
        presentation: None,
    });
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('3'), &mut writer);
    assert!(model.visible_rows().is_empty());
    reduce(&mut model, UiEvent::Character('4'), &mut writer);
    assert_eq!(model.visible_rows(), vec![0]);
    reduce(&mut model, UiEvent::Character('5'), &mut writer);
    assert!(model.visible_rows().is_empty());
    reduce(&mut model, UiEvent::Character('2'), &mut writer);
    assert_eq!(model.visible_rows(), vec![0, 1]);
}

#[test]
fn public_info_has_its_own_filter_category() {
    let mut model = model(false);
    model.rows.push(Row {
        depth: 0,
        name: "known-hosts".into(),
        display_segments: vec![],
        path: Some("h.services.backup.known-hosts".into()),
        is_set: true,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: Some("Pinned SSH host identity".into()),
        category: RowCategory::PublicInfo,
        human_facing: false,
        external_input_required: true,
        identity: None,
        presentation: None,
    });
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('5'), &mut writer);
    assert_eq!(model.visible_rows(), vec![1]);
    reduce(&mut model, UiEvent::Character('2'), &mut writer);
    assert_eq!(model.visible_rows(), vec![0, 1]);
}

#[test]
fn refreshed_rows_preserve_selection_and_propagate_shared_public_status() {
    let mut model = model(false);
    let mut shared = model.rows[0].clone();
    shared.name = "known-hosts".into();
    shared.path = Some("h.services.backup.known-hosts".into());
    shared.category = RowCategory::PublicInfo;
    model.rows.push(shared);
    model.set_filter(crate::model::ViewFilter::All);
    model.selected = 1;
    let mut refreshed = model.rows.clone();
    refreshed[1].is_set = true;
    model.update_rows(refreshed);
    assert_eq!(model.selected().unwrap().name, "known-hosts");
    assert!(model.selected().unwrap().is_set);
}

#[test]
fn human_filter_and_search_compose() {
    let mut model = model(true);
    model.rows[0].human_facing = true;
    model.rows[0].description = Some("Human login password".into());
    model.rows.push(Row {
        depth: 0,
        name: "service-token".into(),
        display_segments: vec![],
        path: Some("h.services.s.service-token".into()),
        is_set: true,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Other,
        human_facing: false,
        external_input_required: true,
        identity: None,
        presentation: None,
    });
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('h'), &mut writer);
    assert_eq!(model.visible_rows(), vec![0]);
    reduce(&mut model, UiEvent::Character('/'), &mut writer);
    for character in "login".chars() {
        reduce(&mut model, UiEvent::Character(character), &mut writer);
    }
    assert_eq!(model.visible_rows(), vec![0]);
    reduce(&mut model, UiEvent::Character('z'), &mut writer);
    assert!(model.visible_rows().is_empty());
    reduce(&mut model, UiEvent::Escape, &mut writer);
    assert_eq!(model.visible_rows(), vec![0]);
}

#[test]
fn mouse_clicks_select_without_editing_and_shortcuts_use_keyboard_behavior() {
    let mut model = model(false);
    let mut second = model.rows[0].clone();
    second.name = "other".into();
    second.path = Some("h.services.s.other".into());
    model.rows.push(second);
    let mut writer = writer();
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Tree(1)),
        &mut writer,
    );
    assert_eq!(model.selected, 1);
    assert!(matches!(model.mode, Mode::Browse));
    assert!(writer.writes.is_empty());
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Filter(3)),
        &mut writer,
    );
    assert_eq!(model.filter, crate::model::ViewFilter::Keys);
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Shortcut(Shortcut::Character('?'))),
        &mut writer,
    );
    assert!(matches!(model.mode, Mode::Help { .. }));
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Tree(0)),
        &mut writer,
    );
    assert!(matches!(model.mode, Mode::Help { .. }));
}

#[test]
fn ticks_copy_the_writer_activity_into_the_model() {
    struct Busy(Writer, u8);
    impl SecretWriter for Busy {
        fn write(
            &mut self,
            path: &str,
            value: Zeroizing<Vec<u8>>,
        ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
            self.0.write(path, value)
        }
        fn activity(&mut self) -> Option<crate::model::Activity> {
            self.1 += 1;
            (self.1 == 1).then(|| crate::model::Activity {
                label: "Decrypting h.services.s.key".into(),
                waits_for_one_password: true,
                started: std::time::Instant::now(),
            })
        }
    }
    let mut frontend = FakeFrontend {
        events: VecDeque::from([UiEvent::Tick, UiEvent::Escape]),
        draws: 0,
    };
    let mut model = model(true);
    let mut writer = Busy(writer(), 0);
    drive(&mut frontend, &mut writer, &mut model).unwrap();
    assert_eq!(
        model
            .activity
            .as_ref()
            .map(|activity| activity.label.as_str()),
        Some("Decrypting h.services.s.key")
    );
}

#[test]
fn clicking_a_selected_unset_input_value_opens_entry() {
    let mut model = model(false);
    let mut second = model.rows[0].clone();
    second.name = "other".into();
    second.path = Some("h.services.s.other".into());
    model.rows.push(second);
    let mut writer = writer();
    let click = |model: &mut Model, writer: &mut Writer, index| {
        reduce(model, UiEvent::Click(MouseTarget::Tree(index)), writer);
    };
    click(&mut model, &mut writer, 1);
    assert!(
        matches!(model.mode, Mode::Browse),
        "first click only selects"
    );
    click(&mut model, &mut writer, 1);
    assert!(
        matches!(model.mode, Mode::Edit { .. }),
        "second click opens entry"
    );

    model.mode = Mode::Browse;
    model.rows[1].external_input_required = false;
    click(&mut model, &mut writer, 1);
    assert!(
        matches!(model.mode, Mode::Browse),
        "generated values are never entered by clicking"
    );
    model.rows[1].external_input_required = true;
    model.rows[1].is_set = true;
    click(&mut model, &mut writer, 1);
    assert!(
        matches!(model.mode, Mode::Browse),
        "set values are not replaced"
    );
    assert!(writer.writes.is_empty());
}
