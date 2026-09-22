use super::{submit, Action, Mode, Model, SecretWriter, UiEvent};

pub(super) fn begin(model: &mut Model, writer: &mut impl SecretWriter) {
    let selected = model.selected().cloned();
    let Some(row) = selected.filter(|row| row.is_secret()) else {
        model.message = Some("select a secret leaf to generate".into());
        return;
    };
    if !row.can_generate {
        model.message = Some("generation is not authorized for this secret".into());
        return;
    }
    let path = row.path.expect("secret row has path");
    match writer.generate(&path) {
        Ok(value) => {
            model.mode = Mode::GeneratedPreview {
                path,
                value,
                revealed: false,
                replacing: row.is_set,
            }
        }
        Err(message) => model.message = Some(message),
    }
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
