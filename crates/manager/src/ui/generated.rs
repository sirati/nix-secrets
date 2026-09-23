use super::{submit, Action, GenerateKind, Mode, Model, SecretWriter, UiEvent};

pub(super) fn begin(model: &mut Model, _writer: &mut impl SecretWriter) {
    let selected = model.selected().cloned();
    let Some(row) = selected.filter(|row| row.is_secret()) else {
        model.message = Some("select a password leaf".into());
        return;
    };
    if !row.can_generate {
        model.message = Some("select a password leaf".into());
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
    match writer.generate(&path, kind) {
        Ok(value) => {
            model.mode = Mode::GeneratedPreview {
                path,
                value,
                revealed: false,
                replacing,
            }
        }
        Err(message) => model.message = Some(message),
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
            model.message = Some(match writer.copy(&value) {
                Ok(()) => "generated value copied".into(),
                Err(error) => error,
            });
            model.mode = Mode::GeneratedPreview {
                path,
                value,
                revealed,
                replacing,
            };
        }
        UiEvent::Enter if replacing => model.mode = Mode::Replace { path, value },
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
