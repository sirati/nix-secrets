use super::{
    fail_unless_queued, report, submit, Action, GenerateKind, Mode, Model, SecretWriter, UiEvent,
};

pub(super) fn begin(model: &mut Model, _writer: &mut impl SecretWriter) {
    let selected = model.selected().cloned();
    let Some(row) = selected.filter(|row| row.is_secret()) else {
        model.inform("select a password leaf");
        return;
    };
    if !row.can_generate {
        model.inform("select a password leaf");
        return;
    }
    let path = row.path.expect("secret row has path");
    model.mode = Mode::GenerateChoice {
        path,
        replacing: row.is_set,
    };
}

pub(super) fn choose(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    choice: Mode,
    event: UiEvent,
) -> Action {
    let Mode::GenerateChoice { path, replacing } = choice else {
        unreachable!()
    };
    let kind = match event {
        UiEvent::Character('p') => GenerateKind::Password,
        UiEvent::Character('w') => GenerateKind::Passphrase,
        UiEvent::Escape => return Action::Continue,
        _ => {
            model.mode = Mode::GenerateChoice { path, replacing };
            return Action::Continue;
        }
    };
    match writer.generate_for(&path, kind, replacing) {
        Ok(value) => {
            model.mode = Mode::GeneratedPreview {
                path,
                value,
                revealed: false,
                replacing,
            }
        }
        Err(message) => fail_unless_queued(model, message),
    }
    Action::Continue
}

pub(super) fn reduce(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    preview: Mode,
    event: UiEvent,
) -> Action {
    let Mode::GeneratedPreview {
        path,
        value,
        revealed,
        replacing,
    } = preview
    else {
        unreachable!("generated reducer receives a generated preview")
    };
    match event {
        UiEvent::Character('r') => {
            model.mode = Mode::GeneratedPreview {
                path,
                value,
                revealed: !revealed,
                replacing,
            };
        }
        UiEvent::Character('c') => {
            report(
                model,
                writer
                    .copy(&value)
                    .map(|()| "generated value copied".into()),
            );
            model.mode = Mode::GeneratedPreview {
                path,
                value,
                revealed,
                replacing,
            };
        }
        UiEvent::Enter if replacing => {
            let commit = writer.commit_state(&path);
            model.mode = Mode::Replace {
                path,
                value,
                commit,
            }
        }
        UiEvent::Enter => submit(model, writer, path, value),
        UiEvent::Escape => {}
        _ => {
            model.mode = Mode::GeneratedPreview {
                path,
                value,
                revealed,
                replacing,
            }
        }
    }
    Action::Continue
}
