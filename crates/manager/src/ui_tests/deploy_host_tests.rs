//! `D` and the host picker, and the partial-deployment choice in the
//! approval dialog.
use super::*;

#[derive(Default)]
struct DeployWriter {
    requested: Vec<String>,
    approvals: Vec<&'static str>,
}

impl SecretWriter for DeployWriter {
    fn write(
        &mut self,
        _path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        Err(("unused".into(), value))
    }
    fn request_deployment(&mut self, host: &str) -> Result<(), String> {
        self.requested.push(host.to_owned());
        Ok(())
    }
    fn approval(&mut self, accepted: bool) -> Result<Option<ApprovalRequest>, String> {
        self.approvals.push(if accepted { "full" } else { "reject" });
        Ok(None)
    }
}

fn leaf(path: &str) -> Row {
    Row {
        depth: 1,
        name: path.rsplit('.').next().unwrap().into(),
        display_segments: vec![],
        path: Some(path.into()),
        is_set: false,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Key,
        human_facing: false,
        external_input_required: false,
        required_for_install: false,
        identity: None,
        presentation: None,
    }
}

/// Two hosts in the default tree: `alpha` and `ns1`.
fn hosts_model() -> Model {
    let mut model = Model::new(vec![
        leaf("ns1.services.dns.update-key"),
        leaf("alpha.services.web.token"),
        leaf("ns1.services.dns.transfer-key"),
    ]);
    model.rebuild_tree();
    model.set_filter(crate::model::ViewFilter::All);
    model
}

fn select_value(model: &mut Model, path: &str) {
    model.selected = model
        .visible_rows()
        .iter()
        .position(|index| model.rows[*index].path.as_deref() == Some(path))
        .expect("value is visible");
}

#[test]
fn d_opens_the_host_picker_with_the_selected_rows_host() {
    let mut model = hosts_model();
    let mut writer = DeployWriter::default();
    assert_eq!(model.deploy_hosts(), ["alpha", "ns1"]);
    select_value(&mut model, "ns1.services.dns.transfer-key");
    reduce(&mut model, UiEvent::Character('D'), &mut writer);
    assert_eq!(model.mode, Mode::DeployHost { selected: 1 });
    // A group whose values all belong to one host preselects it too.
    model.mode = Mode::Browse;
    model.selected = 0;
    assert!(!model.selected().unwrap().is_secret());
    assert_eq!(model.selected_host().as_deref(), Some("alpha"));
    reduce(&mut model, UiEvent::Character('D'), &mut writer);
    assert_eq!(model.mode, Mode::DeployHost { selected: 0 });
    assert!(writer.requested.is_empty(), "opening the picker requests nothing");
}

#[test]
fn the_picker_moves_confirms_and_cancels() {
    let mut model = hosts_model();
    let mut writer = DeployWriter::default();
    reduce(&mut model, UiEvent::Character('D'), &mut writer);
    reduce(&mut model, UiEvent::Down, &mut writer);
    reduce(&mut model, UiEvent::Down, &mut writer);
    assert_eq!(model.mode, Mode::DeployHost { selected: 1 }, "stops at the last host");
    reduce(&mut model, UiEvent::Up, &mut writer);
    reduce(&mut model, UiEvent::Escape, &mut writer);
    assert_eq!(model.mode, Mode::Browse);
    assert!(writer.requested.is_empty());
    reduce(&mut model, UiEvent::Character('D'), &mut writer);
    reduce(&mut model, UiEvent::Down, &mut writer);
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert_eq!(writer.requested, ["ns1"]);
    assert_eq!(model.mode, Mode::Browse);
    // The request comes back as an ordinary approval.
    assert!(writer.approvals.is_empty());
}

#[test]
fn the_deploy_button_and_a_picker_click_request_the_host() {
    let mut model = hosts_model();
    let mut writer = DeployWriter::default();
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Shortcut(Shortcut::Character('D'))),
        &mut writer,
    );
    assert!(matches!(model.mode, Mode::DeployHost { .. }));
    reduce(&mut model, UiEvent::Click(MouseTarget::ModalItem(1)), &mut writer);
    assert_eq!(writer.requested, ["ns1"]);
}

#[test]
fn an_empty_schema_has_nothing_to_deploy() {
    let mut model = Model::new(vec![]);
    let mut writer = DeployWriter::default();
    reduce(&mut model, UiEvent::Character('D'), &mut writer);
    assert_eq!(model.mode, Mode::Browse);
    assert!(model.message_text().unwrap().contains("no hosts"));
}

fn waiting_request() -> ApprovalRequest {
    ApprovalRequest {
        id: "deploy-1".into(),
        target: "ns1".into(),
        create: vec![
            "ns1.services.dns.transfer-key".into(),
            "ns1.services.dns.update-key".into(),
        ],
        replace: vec![],
        recipient_keys: vec!["operator".into()],
        host_key: None,
        tasks: vec![],
        generate: vec![("ns1.services.dns.transfer-key".into(), "key".into())],
        missing: vec![(
            "ns1.services.dns.update-key".into(),
            "derived from unset mail.services.stalwart.dns-update-key; deploy mail first, which generates it".into(),
        )],
        derived: vec![],
        skippable: vec!["ns1.services.dns.update-key".into()],
        missing_kinds: Default::default(),
        host_default: vec![],
        allow_partial: false,
        ..Default::default()
    }
}

#[test]
fn missing_values_never_block_and_y_deploys_the_rest() {
    let mut model = hosts_model();
    let mut writer = DeployWriter::default();
    reduce(&mut model, UiEvent::Approval(waiting_request()), &mut writer);
    let Mode::Approval(request) = &model.mode else {
        panic!("the approval: {:?}", model.mode)
    };
    assert!(request.deployable());
    assert_eq!(
        reduce(&mut model, UiEvent::Character('y'), &mut writer),
        Action::Approved
    );
    assert_eq!(writer.approvals, ["full"]);
}

#[test]
fn a_request_with_nothing_to_deploy_offers_no_approve() {
    let mut model = hosts_model();
    let mut writer = DeployWriter::default();
    let mut request = waiting_request();
    request.create.clear();
    request.generate.clear();
    reduce(&mut model, UiEvent::Approval(request), &mut writer);
    let Mode::Approval(request) = &model.mode else {
        panic!("the approval: {:?}", model.mode)
    };
    assert!(!request.deployable());
    assert_eq!(
        reduce(&mut model, UiEvent::Character('n'), &mut writer),
        Action::Rejected
    );
    assert_eq!(writer.approvals, ["reject"]);
}
