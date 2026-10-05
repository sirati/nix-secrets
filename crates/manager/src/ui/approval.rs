use super::*;

pub(super) fn reduce(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    mut request: ApprovalRequest,
    event: UiEvent,
) -> Action {
    if !request.host_mutations.is_empty() {
        return host_mutations(model, writer, request, event);
    }
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

fn host_mutations(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    request: ApprovalRequest,
    event: UiEvent,
) -> Action {
    let accepted = match event {
        UiEvent::Character('y') => true,
        UiEvent::Character('n') | UiEvent::Escape => false,
        UiEvent::Up | UiEvent::Down => {
            model.modal_scroll = model.scrolled(model.modal_scroll, event == UiEvent::Down);
            model.mode = Mode::Approval(request);
            return Action::Continue;
        }
        _ => {
            model.mode = Mode::Approval(request);
            return Action::Continue;
        }
    };
    let Some(token) = request
        .host_mutation_token
        .as_deref()
        .filter(|token| !token.is_empty())
    else {
        model.fail("This replacement review has no batch identifier; no values were changed.");
        model.mode = Mode::Approval(request);
        return Action::Continue;
    };
    match writer.approve_host_mutations(accepted, token) {
        Ok(Some(next)) => model.mode = Mode::Approval(next),
        Ok(None) => {
            return if accepted {
                Action::Approved
            } else {
                Action::Rejected
            }
        }
        Err(message) => {
            let queued = message == OPERATION_QUEUED;
            fail_unless_queued(model, message);
            if !queued {
                model.mode = Mode::Approval(request);
            }
        }
    }
    Action::Continue
}

#[cfg(test)]
mod host_mutation_tests {
    use super::*;
    use crate::model::HostMutationReview;
    struct Writer {
        decisions: Vec<(bool, String)>,
    }
    impl SecretWriter for Writer {
        fn write(
            &mut self,
            _: &str,
            value: Zeroizing<Vec<u8>>,
        ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
            Err(("unused".into(), value))
        }
        fn approval(&mut self, _: bool) -> Result<Option<ApprovalRequest>, String> {
            panic!("ordinary deployment approval must never authorize a host replacement")
        }
        fn approve_host_mutations(
            &mut self,
            accepted: bool,
            token: &str,
        ) -> Result<Option<ApprovalRequest>, String> {
            self.decisions.push((accepted, token.into()));
            Ok(None)
        }
    }
    fn request() -> ApprovalRequest {
        ApprovalRequest {
            id: "same-deploy".into(),
            target: "producer".into(),
            host_mutation_token: Some("shown-batch".into()),
            host_mutations: vec![HostMutationReview {
                identifier: "receiver.services.report.known-hosts".into(),
                kind: "report receiver host identity".into(),
                previous: vec!["SHA256:old".into()],
                proposed: vec!["SHA256:new".into()],
            }],
            ..Default::default()
        }
    }
    #[test]
    fn consent_and_rejection_send_only_the_exact_displayed_batch_token() {
        for (event, accepted, action) in [
            (UiEvent::Character('y'), true, Action::Approved),
            (UiEvent::Character('n'), false, Action::Rejected),
            (UiEvent::Escape, false, Action::Rejected),
        ] {
            let mut model = Model::new(vec![]);
            let mut writer = Writer { decisions: vec![] };
            model.mode = Mode::Approval(request());
            assert_eq!(crate::ui::reduce(&mut model, event, &mut writer), action);
            assert_eq!(writer.decisions, vec![(accepted, "shown-batch".into())]);
        }
    }
    #[test]
    fn entering_or_toggling_never_approves_and_missing_token_fails_closed() {
        let mut model = Model::new(vec![]);
        let mut writer = Writer { decisions: vec![] };
        model.mode = Mode::Approval(request());
        for event in [
            UiEvent::Enter,
            UiEvent::Character(' '),
            UiEvent::Character('a'),
            UiEvent::Click(MouseTarget::DeployRow(0)),
        ] {
            crate::ui::reduce(&mut model, event, &mut writer);
            assert!(writer.decisions.is_empty());
            assert!(matches!(model.mode, Mode::Approval(_)));
        }
        let mut malformed = request();
        malformed.host_mutation_token = None;
        model.mode = Mode::Approval(malformed);
        crate::ui::reduce(&mut model, UiEvent::Character('y'), &mut writer);
        assert!(writer.decisions.is_empty());
    }
}
