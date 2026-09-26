use super::*;

pub(super) fn reduce(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    request: ApprovalRequest,
    event: UiEvent,
) -> Action {
    match event {
        UiEvent::Character('y') => {
            // A partial deployment tells the controller to skip the values
            // that wait for another host; otherwise it refuses as before.
            let result = if request.allow_partial && request.partial_possible() {
                writer.approve_partial()
            } else {
                writer.approval(true)
            };
            match result {
                Ok(Some(next)) => model.mode = Mode::Approval(next),
                Ok(None) => return Action::Approved,
                // A failed deployment is final: the request is resolved with
                // the error and never re-offered, so the dialog closes.
                Err(message) => fail_unless_queued(model, message),
            }
        }
        // Switches between refusing and deploying everything else while
        // skipping the values that wait for another host. Offered only when
        // every missing value is such a value, and never before the host key
        // is trusted. Nothing is deployed until y.
        UiEvent::Character('p') if request.host_key.is_none() && request.partial_possible() => {
            model.mode = Mode::Approval(ApprovalRequest {
                allow_partial: !request.allow_partial,
                ..request
            });
        }
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
