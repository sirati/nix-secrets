//! The Git Commit dialog.
use super::*;
use nix_secrets_core::git::{CommitOptions, CommitResult, CommitSummary};

#[derive(Default)]
struct CommitWriter {
    summary: CommitSummary,
    commits: Vec<CommitOptions>,
    fail: Option<String>,
}

impl SecretWriter for CommitWriter {
    fn write(
        &mut self,
        _path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        Err(("unused".into(), value))
    }
    fn commit_summary(&mut self) -> Result<CommitSummary, String> {
        Ok(self.summary.clone())
    }
    fn commit(&mut self, options: CommitOptions) -> Result<CommitResult, String> {
        self.commits.push(options);
        match &self.fail {
            Some(error) => Err(error.clone()),
            None => Ok(CommitResult {
                hash: "0123456789abcdef".into(),
                output: "[0123456] Store secrets".into(),
            }),
        }
    }
}

fn changed() -> CommitSummary {
    CommitSummary {
        diff_stat: " nix-secrets.toml | 2 +-".into(),
        changed: vec![" M nix-secrets.toml".into()],
        foreign_staged: vec![],
        head_message: Some("Previous subject\n\nPrevious body".into()),
        signs: true,
    }
}

fn open(writer: &mut CommitWriter) -> Model {
    let mut model = model(true);
    reduce(&mut model, UiEvent::Character('C'), writer);
    assert!(
        matches!(model.mode, Mode::Commit { .. }),
        "{:?}",
        model.mode
    );
    model
}

fn typed(model: &mut Model, writer: &mut CommitWriter, text: &str) {
    for character in text.chars() {
        let event = if character == '\n' {
            UiEvent::Enter
        } else {
            UiEvent::Character(character)
        };
        reduce(model, event, writer);
    }
}

fn draft(model: &Model) -> crate::model::CommitDraft {
    match &model.mode {
        Mode::Commit { draft, .. } => draft.clone(),
        other => panic!("not the commit dialog: {other:?}"),
    }
}

#[test]
fn typing_checkboxes_and_commit() {
    let mut writer = CommitWriter {
        summary: changed(),
        ..CommitWriter::default()
    };
    let mut model = open(&mut writer);
    // Keys that act in the tree are plain text here.
    typed(&mut model, &mut writer, "Store dy\nd g C");
    reduce(&mut model, UiEvent::Backspace, &mut writer);
    assert_eq!(draft(&model).message, "Store dy\nd g ");
    reduce(&mut model, UiEvent::ToggleSignoff, &mut writer);
    reduce(&mut model, UiEvent::Submit, &mut writer);
    assert_eq!(
        writer.commits,
        [CommitOptions {
            message: "Store dy\nd g ".into(),
            amend: false,
            signoff: true,
        }]
    );
    assert!(matches!(model.mode, Mode::Browse));
    let notice = model.message_text().unwrap();
    assert!(notice.contains("0123456789abcdef"), "{notice}");
    assert!(notice.contains("[0123456] Store secrets"), "{notice}");
    assert_eq!(
        model.commit_draft,
        Default::default(),
        "a commit clears the draft"
    );
}

#[test]
fn clicks_toggle_the_checkboxes_and_commit() {
    let mut writer = CommitWriter {
        summary: changed(),
        ..CommitWriter::default()
    };
    let mut model = open(&mut writer);
    typed(&mut model, &mut writer, "Subject");
    for target in [
        MouseTarget::CommitSignoff,
        MouseTarget::CommitSignoff,
        MouseTarget::CommitSignoff,
    ] {
        reduce(&mut model, UiEvent::Click(target), &mut writer);
    }
    assert!(draft(&model).signoff);
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::CommitAmend),
        &mut writer,
    );
    assert!(draft(&model).amend);
    assert_eq!(draft(&model).message, "Subject", "a typed message is kept");
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::CommitSubmit),
        &mut writer,
    );
    assert!(writer.commits[0].amend && writer.commits[0].signoff);
}

#[test]
fn amend_prefills_the_last_message_into_an_empty_field() {
    let mut writer = CommitWriter {
        summary: changed(),
        ..CommitWriter::default()
    };
    let mut model = open(&mut writer);
    reduce(&mut model, UiEvent::Tab, &mut writer);
    assert!(draft(&model).amend);
    assert_eq!(draft(&model).message, "Previous subject\n\nPrevious body");
}

#[test]
fn empty_messages_and_foreign_staged_changes_are_refused() {
    let mut writer = CommitWriter {
        summary: changed(),
        ..CommitWriter::default()
    };
    let mut model = open(&mut writer);
    typed(&mut model, &mut writer, " \n");
    reduce(&mut model, UiEvent::Submit, &mut writer);
    assert!(writer.commits.is_empty());
    assert!(model.message_text().unwrap().contains("message"));
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert!(
        matches!(model.mode, Mode::Commit { .. }),
        "the dialog stays"
    );

    writer.summary.foreign_staged = vec!["flake.nix".into()];
    let mut model = open(&mut writer);
    typed(&mut model, &mut writer, "Subject");
    reduce(&mut model, UiEvent::Submit, &mut writer);
    assert!(writer.commits.is_empty());
    assert!(model.message_text().unwrap().contains("flake.nix"));
}

#[test]
fn a_failed_commit_keeps_the_draft_and_shows_gits_error() {
    let mut writer = CommitWriter {
        summary: changed(),
        fail: Some(
            "error: gpg failed to sign the data\nfatal: failed to write commit object".into(),
        ),
        ..CommitWriter::default()
    };
    let mut model = open(&mut writer);
    typed(&mut model, &mut writer, "Subject");
    reduce(&mut model, UiEvent::Submit, &mut writer);
    assert!(model
        .message_text()
        .unwrap()
        .contains("failed to write commit object"));
    reduce(&mut model, UiEvent::Enter, &mut writer);
    // Esc closes the dialog; reopening restores the draft.
    reduce(&mut model, UiEvent::Escape, &mut writer);
    assert!(matches!(model.mode, Mode::Browse));
    reduce(&mut model, UiEvent::Character('C'), &mut writer);
    assert_eq!(draft(&model).message, "Subject");
}

#[test]
fn a_queued_commit_result_arrives_as_a_completion() {
    let mut model = model(true);
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::CommitSummary(changed()),
    );
    assert!(matches!(model.mode, Mode::Commit { .. }));
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::CommitFailed("fatal: bad".into()),
    );
    assert!(model.message_text().unwrap().contains("fatal: bad"));
    model.acknowledge();
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::Committed(CommitResult {
            hash: "abc".into(),
            output: "[abc] x".into(),
        }),
    );
    assert!(matches!(model.mode, Mode::Browse));
}

/// A frontend whose editor is a real script, as `$EDITOR` would be.
struct EditingFrontend {
    events: VecDeque<UiEvent>,
    editor: String,
}
impl Frontend for EditingFrontend {
    fn draw(&mut self, _model: &Model) -> io::Result<()> {
        Ok(())
    }
    fn read(&mut self, _timeout: std::time::Duration) -> io::Result<UiEvent> {
        Ok(self.events.pop_front().unwrap())
    }
    fn edit(&mut self, text: &str) -> Result<String, String> {
        crate::editor::edit_with(&self.editor, text)
    }
}

#[test]
fn the_editor_round_trip_replaces_the_message() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = tempfile::tempdir().unwrap();
    let script = scratch.path().join("editor");
    // Appends a body to whatever the dialog held.
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf '\\n\\nWritten in the editor\\n' >> \"$1\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut writer = CommitWriter {
        summary: changed(),
        ..CommitWriter::default()
    };
    let mut model = open(&mut writer);
    typed(&mut model, &mut writer, "Subject");
    let mut frontend = EditingFrontend {
        events: VecDeque::from([
            UiEvent::Click(MouseTarget::CommitEditor),
            UiEvent::Submit,
            // The first Esc closes the success notice, the second quits.
            UiEvent::Escape,
            UiEvent::Escape,
        ]),
        editor: script.display().to_string(),
    };
    drive(&mut frontend, &mut writer, &mut model).unwrap();
    assert_eq!(
        writer.commits[0].message,
        "Subject\n\nWritten in the editor"
    );
}
