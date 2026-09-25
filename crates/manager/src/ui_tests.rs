use crate::model::{ApprovalRequest, Mode, Model, TaskApproval};
use crate::tree::{Row, RowCategory};
use crate::ui::{
    drive, reduce, Action, Frontend, GenerateKind, MouseTarget, SecretWriter, Shortcut, UiEvent,
};
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
    clipboard: Option<Vec<u8>>,
    commit: Option<nix_secrets_core::CommitState>,
}
impl SecretWriter for Writer {
    fn generate_missing(&mut self, paths: Vec<String>, _kind: GenerateKind) -> Result<(), String> {
        self.bulk.push(paths);
        Ok(())
    }
    fn generate(&mut self, _path: &str, _kind: GenerateKind) -> Result<Zeroizing<Vec<u8>>, String> {
        Ok(Zeroizing::new(b"generated-value".to_vec()))
    }
    fn commit_state(&mut self, _path: &str) -> nix_secrets_core::CommitState {
        self.commit
            .clone()
            .unwrap_or(nix_secrets_core::CommitState::Committed)
    }
    fn paste(&mut self) -> Result<Zeroizing<Vec<u8>>, String> {
        self.clipboard
            .clone()
            .map(Zeroizing::new)
            .ok_or_else(|| "cannot read the clipboard: no tool".into())
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
        display_segments: vec![],
        path: Some("h.services.s.key".into()),
        is_set: set,
        is_task: false,
        can_generate: true,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Password,
        human_facing: false,
        external_input_required: true,
        identity: None,
        presentation: None,
    }])
}

#[test]
fn browse_copy_secret_and_public_key_use_distinct_actions() {
    let mut model = model(true);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('c'), &mut writer);
    // The success notice closes and p still copies the public key.
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
        display_segments: vec![],
        path: Some("h.services.backup.bootstrap".into()),
        is_set: false,
        is_task: true,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Password,
        human_facing: false,
        external_input_required: true,
        identity: None,
        presentation: None,
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
        clipboard: None,
        commit: None,
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
    let mut external = model.rows[0].clone();
    external.name = "external-password".into();
    external.path = Some("h.services.s.external-password".into());
    external.external_input_required = true;
    external.can_generate = false;
    model.rows.push(external);
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

#[test]
fn bracketed_paste_fills_the_entry_dialog_even_after_a_success_notice() {
    let mut model = model(false);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert!(matches!(model.mode, Mode::Edit { .. }));
    reduce(&mut model, UiEvent::Paste(b"pasted".to_vec()), &mut writer);
    model.inform("copied public key");
    reduce(&mut model, UiEvent::Paste(b"-more".to_vec()), &mut writer);
    assert!(model.message.is_none());
    let Mode::Edit { value, .. } = &model.mode else {
        panic!("entry closed")
    };
    assert_eq!(value.as_slice(), b"pasted-more");
    assert!(!format!("{:?}", model.mode).contains("pasted"), "masked");
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert_eq!(writer.writes, [b"pasted-more"]);
}

#[test]
fn ctrl_v_reads_the_clipboard_once_or_reports_why_not() {
    let mut model = model(false);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Enter, &mut writer);
    reduce(&mut model, UiEvent::PasteRequest, &mut writer);
    assert_eq!(
        model.message_text(),
        Some("cannot read the clipboard: no tool")
    );
    reduce(&mut model, UiEvent::Enter, &mut writer);
    writer.clipboard = Some(b"from-clipboard".to_vec());
    reduce(&mut model, UiEvent::PasteRequest, &mut writer);
    let Mode::Edit { value, .. } = &model.mode else {
        panic!("entry closed")
    };
    assert_eq!(value.as_slice(), b"from-clipboard");
}

#[test]
fn ctrl_v_in_the_tree_sets_an_unset_leaf_like_a_terminal_paste() {
    let mut model = model(false);
    let mut writer = writer();
    writer.clipboard = Some(b"direct".to_vec());
    reduce(&mut model, UiEvent::PasteRequest, &mut writer);
    assert_eq!(writer.writes, [b"direct"]);
}

#[test]
fn autosave_saves_a_one_line_paste_into_an_unset_value() {
    let mut model = model(false);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('O'), &mut writer);
    assert!(matches!(model.mode, Mode::Settings { .. }));
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert!(
        model.settings.autosave_unset_on_paste,
        "toggled in settings"
    );
    reduce(&mut model, UiEvent::Escape, &mut writer);
    reduce(&mut model, UiEvent::Enter, &mut writer);
    reduce(
        &mut model,
        UiEvent::Paste(b"one-line".to_vec()),
        &mut writer,
    );
    assert_eq!(writer.writes, [b"one-line"], "saved without Enter");
    assert!(matches!(model.mode, Mode::Browse));
    assert_eq!(model.message_text(), Some("saved h.services.s.key"));
}

#[test]
fn autosave_keeps_multi_line_and_empty_pastes_in_the_field() {
    let mut model = model(false);
    let mut writer = writer();
    model.settings.autosave_unset_on_paste = true;
    reduce(&mut model, UiEvent::Enter, &mut writer);
    reduce(
        &mut model,
        UiEvent::Paste(b"two\nlines".to_vec()),
        &mut writer,
    );
    reduce(&mut model, UiEvent::Paste(vec![]), &mut writer);
    assert!(writer.writes.is_empty());
    assert!(matches!(model.mode, Mode::Edit { .. }));
}

#[test]
fn tab_toggles_autosave_from_the_entry_field_for_the_session() {
    let mut model = model(false);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Enter, &mut writer);
    reduce(&mut model, UiEvent::Tab, &mut writer);
    assert!(model.settings.autosave_unset_on_paste);
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::AutosaveToggle),
        &mut writer,
    );
    assert!(
        !model.settings.autosave_unset_on_paste,
        "the checkbox toggles it"
    );
    assert!(matches!(model.mode, Mode::Edit { .. }));
}

#[test]
fn autosave_never_replaces_a_set_value() {
    let mut model = model(true);
    let mut writer = writer();
    model.settings.autosave_unset_on_paste = true;
    reduce(&mut model, UiEvent::Paste(b"new".to_vec()), &mut writer);
    assert!(writer.writes.is_empty());
    assert!(matches!(model.mode, Mode::Replace { .. }));
}

#[test]
fn uncommitted_overwrite_warns_and_only_ctrl_shift_y_confirms() {
    let mut model = model(true);
    let mut writer = writer();
    writer.commit = Some(nix_secrets_core::CommitState::Uncommitted);
    for cancel in [
        UiEvent::Enter,
        UiEvent::Character(' '),
        UiEvent::Character('n'),
        UiEvent::Escape,
    ] {
        reduce(&mut model, UiEvent::Paste(b"new".to_vec()), &mut writer);
        assert!(matches!(
            model.mode,
            Mode::Replace {
                commit: nix_secrets_core::CommitState::Uncommitted,
                ..
            }
        ));
        reduce(&mut model, UiEvent::Character('y'), &mut writer);
        assert!(
            matches!(model.mode, Mode::Replace { .. }),
            "plain y does not confirm"
        );
        reduce(&mut model, cancel, &mut writer);
        assert!(matches!(model.mode, Mode::Browse));
        assert!(writer.writes.is_empty());
    }
    reduce(&mut model, UiEvent::Paste(b"new".to_vec()), &mut writer);
    reduce(&mut model, UiEvent::ConfirmLoss, &mut writer);
    assert_eq!(writer.writes, [b"new"]);
}

#[test]
fn committed_overwrite_keeps_the_plain_confirmation() {
    let mut model = model(true);
    let mut writer = writer();
    writer.commit = Some(nix_secrets_core::CommitState::Committed);
    reduce(&mut model, UiEvent::Paste(b"new".to_vec()), &mut writer);
    reduce(&mut model, UiEvent::Character('y'), &mut writer);
    assert_eq!(writer.writes, [b"new"]);
}
