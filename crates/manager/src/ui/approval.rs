use super::*;

pub(super) fn reduce(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    request: ApprovalRequest,
    event: UiEvent,
) -> Action {
    match event {
        UiEvent::Character('d') => {
            model.approval_details = !model.approval_details;
            model.mode = Mode::Approval(request);
        }
        // Deploys what the dialog lists; missing values never block.
        UiEvent::Character('y') => match writer.approval(true) {
            Ok(Some(next)) => model.mode = Mode::Approval(next),
            Ok(None) => return Action::Approved,
            // A failed deployment is final: the request is resolved with the
            // error and never re-offered, so the dialog closes.
            Err(message) => fail_unless_queued(model, message),
        },
        UiEvent::Character('n') | UiEvent::Escape => match writer.approval(false) {
            Ok(_) => return Action::Rejected,
            Err(message) => {
                fail_unless_queued(model, message);
                model.mode = Mode::Approval(request);
            }
        },
        _ => model.mode = Mode::Approval(request),
    }
    Action::Continue
}
