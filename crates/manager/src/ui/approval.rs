use super::*;

pub(super) fn reduce(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    mut request: ApprovalRequest,
    event: UiEvent,
) -> Action {
    let rows = request.rows();
    match event {
        UiEvent::Character('d') => {
            model.approval_details = !model.approval_details;
            model.mode = Mode::Approval(request);
        }
        // Space toggles the row under the cursor; `a` its whole section.
        UiEvent::Character(' ') if request.host_key.is_none() => {
            if let Some(row) = rows.get(request.cursor) {
                request.toggle(&row.identifier);
            }
            model.mode = Mode::Approval(request);
        }
        UiEvent::Character('a') if request.host_key.is_none() => {
            if let Some(row) = rows.get(request.cursor) {
                request.toggle_section(row.section);
            }
            model.mode = Mode::Approval(request);
        }
        UiEvent::Click(MouseTarget::DeployRow(index)) if index < rows.len() => {
            request.cursor = index;
            request.toggle(&rows[index].identifier);
            model.mode = Mode::Approval(request);
        }
        UiEvent::Up | UiEvent::Down if request.host_key.is_none() && !rows.is_empty() => {
            request.cursor = if event == UiEvent::Up {
                request.cursor.saturating_sub(1)
            } else {
                (request.cursor + 1).min(rows.len() - 1)
            };
            // The dialog follows the cursor: a header or two above it stay
            // visible.
            model.modal_scroll = (request.cursor as u16).saturating_sub(3);
            model.mode = Mode::Approval(request);
        }
        // Deploys the checked rows; missing values never block.
        UiEvent::Character('y') if request.host_key.is_some() || request.deployable() => {
            let unchecked = request.unchecked.clone();
            match writer.approval_with(true, &unchecked) {
                Ok(Some(mut next)) => {
                    next.unchecked = unchecked;
                    model.mode = Mode::Approval(next);
                }
                Ok(None) => return Action::Approved,
                // A failed deployment is final: the request is resolved with the
                // error and never re-offered, so the dialog closes.
                Err(message) => fail_unless_queued(model, message),
            }
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
