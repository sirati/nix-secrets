use super::*;

pub(super) fn click(
    model: &mut Model,
    target: MouseTarget,
    writer: &mut impl SecretWriter,
) -> Action {
    match target {
        MouseTarget::Filter(number)
            if model.message.is_none() && matches!(model.mode, Mode::Browse) =>
        {
            if let Some(character) = char::from_digit(number as u32, 10) {
                reduce(model, UiEvent::Character(character), writer)
            } else {
                Action::Continue
            }
        }
        MouseTarget::Tree(index)
            if model.message.is_none() && matches!(model.mode, Mode::Browse) =>
        {
            if index >= model.visible_rows().len() {
                return Action::Continue;
            }
            // A click selects the row. On a group it also folds or unfolds it.
            // On an unset value that needs operator input it also opens entry,
            // so a list can be filled click by click.
            model.selected = index;
            if model.toggle_selected_group() {
                return Action::Continue;
            }
            if model
                .selected()
                .is_some_and(|row| row.is_secret() && !row.is_set && row.external_input_required)
            {
                model.begin_value(Vec::new());
            }
            Action::Continue
        }
        MouseTarget::CommitAmend
        | MouseTarget::CommitSignoff
        | MouseTarget::CommitEditor
        | MouseTarget::CommitSubmit
            if matches!(model.mode, Mode::Commit { .. }) =>
        {
            commit::click(model, target, writer)
        }
        MouseTarget::ConfirmLoss => reduce(model, UiEvent::ConfirmLoss, writer),
        MouseTarget::AutosaveToggle => reduce(model, UiEvent::Tab, writer),
        MouseTarget::RevealCurrent => reduce(model, UiEvent::RevealCurrent, writer),
        MouseTarget::Shortcut(shortcut) => {
            let event = match shortcut {
                Shortcut::Enter => UiEvent::Enter,
                Shortcut::Escape => UiEvent::Escape,
                Shortcut::Character(character) => UiEvent::Character(character),
            };
            reduce(model, event, writer)
        }
        MouseTarget::ModalItem(index) => match &mut model.mode {
            Mode::FacetCategories { selected }
            | Mode::FacetValues { selected, .. }
            | Mode::Profiles { selected }
            | Mode::Settings { selected } => {
                *selected = index;
                reduce(model, UiEvent::Enter, writer)
            }
            Mode::TreeOrder { selected } => {
                *selected = index;
                Action::Continue
            }
            Mode::FacetFirstChoice { .. } if index < 4 => reduce(
                model,
                UiEvent::Character(char::from_digit(index as u32 + 1, 10).unwrap()),
                writer,
            ),
            _ => Action::Continue,
        },
        _ => Action::Continue,
    }
}
