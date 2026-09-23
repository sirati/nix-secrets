use crate::model::{ApprovalRequest, Mode, Model, TaskApproval};
use crate::tree::Row;
use crate::ui::{drive, reduce, Action, Frontend, GenerateKind, SecretWriter, UiEvent};
use std::collections::VecDeque;
use std::io;
use zeroize::Zeroizing;

struct Writer {
    writes: Vec<Vec<u8>>,
    fail: bool,
    approval: Option<bool>,
    requests: Vec<String>,
    poll_error: bool,
    approval_error: bool,
    copies: Vec<Vec<u8>>,
}
impl SecretWriter for Writer {
    fn generate(&mut self, _path: &str, _kind: GenerateKind) -> Result<Zeroizing<Vec<u8>>, String> {
        Ok(Zeroizing::new(b"generated-value".to_vec()))
    }
    fn copy(&mut self, value: &[u8]) -> Result<(), String> {
        self.copies.push(value.to_vec());
        Ok(())
    }
    fn write(
        &mut self,
        path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        if self.fail {
            return Err(("locked key".into(), value));
        }
        self.writes.push(value.to_vec());
        Ok(Action::Saved(path.into()))
    }
    fn approval(&mut self, accepted: bool) -> Result<Option<ApprovalRequest>, String> {
        if self.approval_error {
            return Err("identity provider is locked".into());
        }
        self.approval = Some(accepted);
        Ok(None)
    }
    fn request_deployment(&mut self, path: &str) -> Result<(), String> {
        self.requests.push(path.into());
        Ok(())
    }
    fn poll_approval(&mut self) -> Result<Option<ApprovalRequest>, String> {
        if self.poll_error {
            Err("approval lease was lost".into())
        } else {
            Ok(None)
        }
    }
}

struct FakeFrontend {
    events: VecDeque<UiEvent>,
    draws: usize,
}
impl Frontend for FakeFrontend {
    fn draw(&mut self, _model: &Model) -> io::Result<()> {
        self.draws += 1;
        Ok(())
    }
    fn read(&mut self) -> io::Result<UiEvent> {
        Ok(self.events.pop_front().unwrap())
    }
}

fn model(set: bool) -> Model {
    Model::new(vec![Row {
        depth: 0,
        name: "key".into(),
        path: Some("h.services.s.key".into()),
        is_set: set,
        is_task: false,
        can_generate: true,
        output_is_set: None,
    }])
}

#[test]
fn explicit_paste_sets_an_unset_leaf() {
    let mut model = model(false);
    let mut writer = writer();
    reduce(
        &mut model,
        UiEvent::Paste(b"from clipboard".to_vec()),
        &mut writer,
    );
    assert_eq!(writer.writes, [b"from clipboard"]);
    assert!(model.rows[0].is_set);
}

#[test]
fn paste_replacement_waits_for_confirmation() {
    let mut model = model(true);
    let mut writer = writer();
    reduce(
        &mut model,
        UiEvent::Paste(b"replacement".to_vec()),
        &mut writer,
    );
    assert!(writer.writes.is_empty());
    reduce(&mut model, UiEvent::Character('y'), &mut writer);
    assert_eq!(writer.writes, [b"replacement"]);
}

#[test]
fn provider_failure_keeps_value_for_retry() {
    let mut model = model(false);
    let mut writer = writer();
    writer.fail = true;
    reduce(&mut model, UiEvent::Paste(b"secret".to_vec()), &mut writer);
    assert!(matches!(model.mode, Mode::ProviderFailure { .. }));
    writer.fail = false;
    reduce(&mut model, UiEvent::Character('r'), &mut writer);
    assert_eq!(writer.writes, [b"secret"]);
}

#[test]
fn approval_is_explicit_and_testable() {
    let mut model = model(false);
    let mut writer = writer();
    let request = ApprovalRequest {
        id: "request".into(),
        target: "host".into(),
        create: vec!["a".into()],
        replace: vec![],
        recipient_keys: vec!["operator".into()],
        host_key: None,
        tasks: vec![],
    };
    reduce(&mut model, UiEvent::Approval(request), &mut writer);
    assert_eq!(
        reduce(&mut model, UiEvent::Character('n'), &mut writer),
        Action::Rejected
    );
    assert_eq!(writer.approval, Some(false));
}

#[test]
fn task_approval_exposes_input_and_target_output_status() {
    let mut model = Model::new(vec![Row {
        depth: 0,
        name: "bootstrap".into(),
        path: Some("h.services.backup.bootstrap".into()),
        is_set: false,
        is_task: true,
        can_generate: false,
        output_is_set: None,
    }]);
    let mut writer = writer();
    let request = ApprovalRequest {
        id: "request".into(),
        target: "h".into(),
        create: vec![],
        replace: vec![],
        recipient_keys: vec!["operator".into()],
        host_key: None,
        tasks: vec![TaskApproval {
            identifier: "h.services.backup.bootstrap".into(),
            input_is_set: true,
            output_is_set: Some(false),
        }],
    };
    assert_eq!(
        reduce(&mut model, UiEvent::Approval(request), &mut writer),
        Action::Continue
    );
    assert!(matches!(model.mode, Mode::Approval(_)));
    assert!(model.rows[0].is_set);
    assert_eq!(model.rows[0].output_is_set, Some(false));
    assert!(writer.approval.is_none());
    assert_eq!(
        reduce(&mut model, UiEvent::Character('y'), &mut writer),
        Action::Approved
    );
    assert_eq!(writer.approval, Some(true));
}

#[test]
fn frontend_is_abstract_for_deterministic_event_loops() {
    let mut frontend = FakeFrontend {
        events: VecDeque::from([UiEvent::Escape]),
        draws: 0,
    };
    let mut writer = writer();
    drive(&mut frontend, &mut writer, &mut model(false)).unwrap();
    assert_eq!(frontend.draws, 1);
}

fn writer() -> Writer {
    Writer {
        writes: vec![],
        fail: false,
        approval: None,
        requests: vec![],
        poll_error: false,
        approval_error: false,
        copies: vec![],
    }
}

mod generation_tests;
#[test]
fn lost_lease_drops_the_modal_and_reports_expiry() {
    let mut frontend = FakeFrontend {
        events: VecDeque::from([UiEvent::Tick, UiEvent::Escape]),
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
    assert_eq!(model.message.as_deref(), Some("approval lease was lost"));
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
    assert_eq!(
        reduce(&mut model, UiEvent::Character('y'), &mut writer),
        Action::Approved
    );
}

#[test]
fn deploy_trigger_submits_only_a_set_selected_leaf() {
    let mut set = model(true);
    let mut writer = writer();
    reduce(&mut set, UiEvent::Character('d'), &mut writer);
    assert_eq!(writer.requests, ["h.services.s.key"]);

    let mut unset = model(false);
    reduce(&mut unset, UiEvent::Character('d'), &mut writer);
    assert_eq!(writer.requests, ["h.services.s.key"]);
    assert_eq!(unset.message.as_deref(), Some("secret is unset"));
}
