use crate::model::{ApprovalRequest, Mode, Model, TaskApproval};
use crate::tree::{Row, RowCategory};
use crate::ui::{drive, reduce, Action, Frontend, GenerateKind, SecretWriter, UiEvent};
use std::collections::VecDeque;
use std::io;
use zeroize::Zeroizing;

struct Writer {
    writes: Vec<Vec<u8>>,
    fail: bool,
    approval: Option<bool>,
    deletions: Vec<String>,
    poll_error: bool,
    approval_error: bool,
    copies: Vec<Vec<u8>>,
    bulk: Vec<Vec<String>>,
}
impl SecretWriter for Writer {
    fn generate_missing(&mut self, paths: Vec<String>, _kind: GenerateKind) -> Result<(), String> {
        self.bulk.push(paths);
        Ok(())
    }
    fn generate(&mut self, _path: &str, _kind: GenerateKind) -> Result<Zeroizing<Vec<u8>>, String> {
        Ok(Zeroizing::new(b"generated-value".to_vec()))
    }
    fn copy(&mut self, value: &[u8]) -> Result<(), String> {
        self.copies.push(value.to_vec());
        Ok(())
    }
    fn copy_public(&mut self, _path: &str) -> Result<(), String> {
        self.copies.push(b"ssh-ed25519 public-key".to_vec());
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
    fn delete(&mut self, path: &str) -> Result<(), String> {
        self.deletions.push(path.into());
        Ok(())
    }
    fn reveal(&mut self, _path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        Ok(Zeroizing::new(b"stored-value".to_vec()))
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
    fn read(&mut self, _timeout: std::time::Duration) -> io::Result<UiEvent> {
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
        description: None,
        category: RowCategory::Password,
        human_facing: false,
    }])
}

#[test]
fn browse_copy_secret_and_public_key_use_distinct_actions() {
    let mut model = model(true);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('c'), &mut writer);
    reduce(&mut model, UiEvent::Enter, &mut writer);
    reduce(&mut model, UiEvent::Character('p'), &mut writer);
    assert_eq!(
        writer.copies,
        [b"stored-value".to_vec(), b"ssh-ed25519 public-key".to_vec()]
    );
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
        description: None,
        category: RowCategory::Password,
        human_facing: false,
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
            requires_input: true,
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
        deletions: vec![],
        poll_error: false,
        approval_error: false,
        copies: vec![],
        bulk: vec![],
    }
}

#[test]
fn bulk_generation_only_requests_unset_passwords() {
    let mut model = model(false);
    let mut already_set = model.rows[0].clone();
    already_set.name = "existing".into();
    already_set.path = Some("h.services.s.existing".into());
    already_set.is_set = true;
    model.rows.push(already_set);
    let mut key = model.rows[0].clone();
    key.name = "private-key".into();
    key.path = Some("h.services.s.private-key".into());
    key.category = RowCategory::Key;
    key.can_generate = false;
    model.rows.push(key);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('G'), &mut writer);
    assert!(matches!(model.mode, Mode::BulkGenerateConfirm { .. }));
    assert!(writer.bulk.is_empty());
    reduce(&mut model, UiEvent::Character('w'), &mut writer);
    assert_eq!(writer.bulk, [vec!["h.services.s.key".to_string()]]);
    assert!(matches!(
        model.mode,
        Mode::BulkProgress { total: 1, done: 0 }
    ));
}

mod generation_tests;
mod navigation_tests;
