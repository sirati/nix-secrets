use super::*;

pub(super) fn reduce(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    failure: Mode,
    event: UiEvent,
) {
    match (failure, event) {
        (Mode::ProviderFailure { path, value, .. }, UiEvent::Character('r') | UiEvent::Enter) => {
            submit(model, writer, path, value);
        }
        // Dismissing an error must not discard the operator's unsaved draft.
        // Escape from the restored entry field explicitly cancels it.
        (Mode::ProviderFailure { path, value, .. }, UiEvent::Escape) => {
            model.mode = Mode::Edit { path, value };
        }
        (failure, _) => model.mode = failure,
    }
}
