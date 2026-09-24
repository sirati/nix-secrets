use super::*;

pub(super) fn reduce(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    failure: Mode,
    event: UiEvent,
) {
    match (failure, event) {
        (Mode::ProviderFailure { path, value, .. }, UiEvent::Character('r')) => {
            submit(model, writer, path, value);
        }
        (Mode::ProviderFailure { .. }, UiEvent::Escape) => {}
        (failure, _) => model.mode = failure,
    }
}
