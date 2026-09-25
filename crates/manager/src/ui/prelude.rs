use super::*;

pub(super) fn handle(
    model: &mut Model,
    event: &UiEvent,
    writer: &mut impl SecretWriter,
) -> Option<Action> {
    match event {
        UiEvent::Hover(target) => {
            model.hover = *target;
            return Some(Action::Continue);
        }
        UiEvent::Click(target) => return Some(mouse::click(model, *target, writer)),
        UiEvent::Approval(request) => {
            model.offer_approval(request.clone());
            return Some(Action::Continue);
        }
        _ => {}
    }
    if model.message.is_some() {
        match event {
            UiEvent::Enter => model.acknowledge(),
            UiEvent::Up => model.modal_scroll = model.modal_scroll.saturating_sub(1),
            UiEvent::Down => model.modal_scroll = model.modal_scroll.saturating_add(1),
            _ => {}
        }
        return Some(Action::Continue);
    }
    if !matches!(
        model.mode,
        Mode::Browse
            | Mode::Help { .. }
            | Mode::Properties { .. }
            | Mode::Reveal { .. }
            | Mode::Edit { .. }
            | Mode::Search { .. }
            | Mode::FacetCategories { .. }
            | Mode::FacetValues { .. }
            | Mode::FacetFirstChoice { .. }
            | Mode::TreeOrder { .. }
            | Mode::Profiles { .. }
            | Mode::ProfileSave { .. }
    ) {
        match event {
            UiEvent::Up => {
                model.modal_scroll = model.modal_scroll.saturating_sub(1);
                return Some(Action::Continue);
            }
            UiEvent::Down => {
                model.modal_scroll = model.modal_scroll.saturating_add(1);
                return Some(Action::Continue);
            }
            _ => {}
        }
    }
    None
}
