use super::*;

pub(super) fn submit_if_edit(model: &mut Model, writer: &mut impl SecretWriter) {
    let mode = std::mem::replace(&mut model.mode, Mode::Browse);
    if let Mode::Edit { path, value } = mode {
        submit(model, writer, path, value);
    } else {
        model.mode = mode;
    }
}

pub(super) fn submit_if_nonempty(model: &mut Model, writer: &mut impl SecretWriter) {
    let mode = std::mem::replace(&mut model.mode, Mode::Browse);
    if let Mode::Edit { path, value } = mode {
        if value.is_empty() {
            model.mode = Mode::Edit { path, value };
        } else {
            submit(model, writer, path, value);
        }
    } else {
        model.mode = mode;
    }
}

pub(super) fn submit(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    path: String,
    value: Zeroizing<Vec<u8>>,
) {
    match writer.write(&path, value) {
        Ok(Action::Saved(saved)) => model.mark_saved(&saved),
        Ok(Action::Queued) => model.message = Some(format!("saving {path}...")),
        Ok(_) => model.mode = Mode::Browse,
        Err((message, value)) => {
            model.mode = Mode::ProviderFailure {
                message,
                path,
                value,
            }
        }
    }
}

pub(super) fn truncate_character(value: &mut Vec<u8>) {
    if let Ok(text) = std::str::from_utf8(value) {
        if let Some((index, _)) = text.char_indices().next_back() {
            value.truncate(index);
        }
    } else {
        value.pop();
    }
}
