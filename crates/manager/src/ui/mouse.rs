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
            if index < model.visible_rows().len() {
                model.selected = index;
            }
            Action::Continue
        }
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
            | Mode::Profiles { selected } => {
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
