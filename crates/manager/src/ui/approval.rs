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
    // Scrolling is line by line from the top, so reaching the last line means
    // every row was displayed. A replacement batch starts again at the top.
    let batch = request.host_mutation_token.clone().unwrap_or_default();
    if model.host_review.as_ref().map(|(token, _)| token) != Some(&batch) {
        model.host_review = Some((batch, false));
        model.modal_scroll = 0;
    }
    if let UiEvent::Up | UiEvent::Down = event {
        model.modal_scroll = model.scrolled(model.modal_scroll, event == UiEvent::Down);
    }
    let batch = request.host_mutation_token.clone().unwrap_or_default();
    if model.host_review_at_end(&batch) {
        model.host_review = Some((batch.clone(), true));
    }
    let accepted = match event {
        // The dialog shows how much is still below and offers Save only once
        // everything has been displayed.
        UiEvent::Character('y') if !model.host_review_seen(&batch) => {
            model.mode = Mode::Approval(request);
            return Action::Continue;
        }
        UiEvent::Character('y') => true,
        UiEvent::Character('n') | UiEvent::Escape => false,
        UiEvent::Up | UiEvent::Down => {
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
    /// What the terminal records when it draws a review `limit` lines too tall.
    fn rendered(model: &Model, batch: &str, limit: u16) {
        *model.host_review_rendered.borrow_mut() = Some(batch.into());
        model.scroll_limit.set(limit);
    }
    #[test]
    fn save_requires_every_line_of_this_batch_to_have_been_displayed() {
        let mut model = Model::new(vec![]);
        let mut writer = Writer { decisions: vec![] };
        model.mode = Mode::Approval(request());
        // Never drawn: nothing was shown, so nothing can be saved.
        crate::ui::reduce(&mut model, UiEvent::Character('y'), &mut writer);
        assert!(writer.decisions.is_empty());
        rendered(&model, "shown-batch", 3);
        for _ in 0..2 {
            crate::ui::reduce(&mut model, UiEvent::Down, &mut writer);
            crate::ui::reduce(&mut model, UiEvent::Character('y'), &mut writer);
            assert!(writer.decisions.is_empty(), "lines remain below");
        }
        crate::ui::reduce(&mut model, UiEvent::Down, &mut writer);
        // Scrolling back up after reading everything keeps the consent valid.
        crate::ui::reduce(&mut model, UiEvent::Up, &mut writer);
        assert_eq!(
            crate::ui::reduce(&mut model, UiEvent::Character('y'), &mut writer),
            Action::Approved
        );
        assert_eq!(writer.decisions, vec![(true, "shown-batch".into())]);
        // Rejecting never requires reading.
        let mut model = Model::new(vec![]);
        let mut writer = Writer { decisions: vec![] };
        model.mode = Mode::Approval(request());
        rendered(&model, "shown-batch", 9);
        assert_eq!(crate::ui::reduce(&mut model, UiEvent::Character('n'), &mut writer), Action::Rejected);
    }
    #[test]
    fn replacement_batch_starts_unread_at_the_top() {
        let mut model = Model::new(vec![]);
        let mut writer = Writer { decisions: vec![] };
        model.mode = Mode::Approval(request());
        rendered(&model, "shown-batch", 2);
        crate::ui::reduce(&mut model, UiEvent::Down, &mut writer);
        crate::ui::reduce(&mut model, UiEvent::Down, &mut writer);
        let mut next = request();
        next.host_mutation_token = Some("next-batch".into());
        model.mode = Mode::Approval(next);
        // A stale limit of 0 from the old dialog proves nothing about this batch.
        model.scroll_limit.set(0);
        crate::ui::reduce(&mut model, UiEvent::Character('y'), &mut writer);
        assert!(writer.decisions.is_empty());
        rendered(&model, "next-batch", 2);
        crate::ui::reduce(&mut model, UiEvent::Character('y'), &mut writer);
        assert!(writer.decisions.is_empty(), "scrolled back to the top, not at its end");
        assert_eq!(model.modal_scroll, 0);
        crate::ui::reduce(&mut model, UiEvent::Down, &mut writer);
        crate::ui::reduce(&mut model, UiEvent::Down, &mut writer);
        crate::ui::reduce(&mut model, UiEvent::Character('y'), &mut writer);
        assert_eq!(writer.decisions, vec![(true, "next-batch".into())]);
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
            rendered(&model, "shown-batch", 0);
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
