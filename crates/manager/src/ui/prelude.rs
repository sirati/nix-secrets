use super::*;
use crate::model::NoticeSeverity;

/// Handles input that precedes mode dispatch. Returns the event when the
/// current mode should still process it.
pub(super) fn handle(
    model: &mut Model,
    event: UiEvent,
    writer: &mut impl SecretWriter,
) -> Result<Action, UiEvent> {
    match event {
        UiEvent::Hover(target) => {
            model.hover = target;
            return Ok(Action::Continue);
        }
        UiEvent::Approval(request) => {
            model.offer_approval(request);
            return Ok(Action::Continue);
        }
        _ => {}
    }
    if let Some(notice) = &model.message {
        return Ok(notice_input(model, notice.severity, event, writer));
    }
    if let UiEvent::Click(target) = event {
        return Ok(mouse::click(model, target, writer));
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
                model.modal_scroll = model.scrolled(model.modal_scroll, false);
                return Ok(Action::Continue);
            }
            UiEvent::Down => {
                model.modal_scroll = model.scrolled(model.modal_scroll, true);
                return Ok(Action::Continue);
            }
            _ => {}
        }
    }
    Err(event)
}

fn notice_input(
    model: &mut Model,
    severity: NoticeSeverity,
    event: UiEvent,
    writer: &mut impl SecretWriter,
) -> Action {
    match (severity, event) {
        (_, UiEvent::Refresh | UiEvent::Tick) => {}
        (NoticeSeverity::Info, UiEvent::Click(MouseTarget::Notice)) => model.acknowledge(),
        (
            NoticeSeverity::Failure,
            UiEvent::Enter | UiEvent::Click(MouseTarget::Shortcut(Shortcut::Enter)),
        ) => model.acknowledge(),
        (NoticeSeverity::Failure, UiEvent::Up) => {
            model.modal_scroll = model.scrolled(model.modal_scroll, false)
        }
        (NoticeSeverity::Failure, UiEvent::Down) => {
            model.modal_scroll = model.scrolled(model.modal_scroll, true)
        }
        (NoticeSeverity::Failure, _) => {}
        // Esc in the tree quits, so it only closes the notice.
        (NoticeSeverity::Info, UiEvent::Escape) => model.acknowledge(),
        // A paste into the tree writes at once, so there it only closes the
        // notice; an open entry field still receives it.
        (NoticeSeverity::Info, event @ (UiEvent::Paste(_) | UiEvent::PasteRequest)) => {
            model.acknowledge();
            if model.message.is_none()
                && matches!(
                    model.mode,
                    Mode::Edit { .. } | Mode::Search { .. } | Mode::ProfileSave { .. }
                )
            {
                return reduce(model, event, writer);
            }
        }
        (NoticeSeverity::Info, event) => {
            model.acknowledge();
            // With another notice queued, the key only advances to it.
            if model.message.is_none() && passes_through(&model.mode) {
                return reduce(model, event, writer);
            }
        }
    }
    Action::Continue
}

/// Modes where a key that dismissed a notice may keep its usual meaning.
/// Confirmations, approvals, generated previews, and value or name entry
/// commit on a single key, so they never receive the dismissing key.
pub(super) fn passes_through(mode: &Mode) -> bool {
    matches!(
        mode,
        Mode::Browse
            | Mode::Help { .. }
            | Mode::Properties { .. }
            | Mode::Reveal { .. }
            | Mode::Search { .. }
            | Mode::FacetCategories { .. }
            | Mode::FacetValues { .. }
            | Mode::FacetFirstChoice { .. }
            | Mode::TreeOrder { .. }
            | Mode::Profiles { .. }
            | Mode::BulkProgress { .. }
    )
}
