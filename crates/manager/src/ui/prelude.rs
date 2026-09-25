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
                model.modal_scroll = model.modal_scroll.saturating_sub(1);
                return Ok(Action::Continue);
            }
            UiEvent::Down => {
                model.modal_scroll = model.modal_scroll.saturating_add(1);
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
            model.modal_scroll = model.modal_scroll.saturating_sub(1)
        }
        (NoticeSeverity::Failure, UiEvent::Down) => {
            model.modal_scroll = model.modal_scroll.saturating_add(1)
        }
        (NoticeSeverity::Failure, _) => {}
        // Pasting in the tree starts a write and Esc in the tree quits, so both
        // only close the notice.
        (NoticeSeverity::Info, UiEvent::Paste(_) | UiEvent::Escape) => model.acknowledge(),
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
