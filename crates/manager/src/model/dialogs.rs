use super::*;

impl Model {
    /// Shows a success or informational notice that any input dismisses.
    pub fn inform(&mut self, message: impl Into<String>) {
        self.push_notice(message.into(), NoticeSeverity::Info);
    }

    /// Shows a failure that stays until the operator explicitly acknowledges it.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.push_notice(message.into(), NoticeSeverity::Failure);
    }

    fn push_notice(&mut self, text: String, severity: NoticeSeverity) {
        let notice = Notice { text, severity };
        if self.message.as_ref() == Some(&notice) || self.notifications.back() == Some(&notice) {
            return;
        }
        if matches!(self.mode, Mode::Browse)
            && severity == NoticeSeverity::Failure
            && self
                .message
                .as_ref()
                .is_some_and(|current| current.severity == NoticeSeverity::Info)
        {
            let displaced = self
                .message
                .replace(notice)
                .expect("informational notice exists");
            self.notifications.push_front(displaced);
            return;
        }
        if self.message.is_none()
            && !matches!(self.mode, Mode::Approval(_))
            && !(severity == NoticeSeverity::Info && matches!(self.mode, Mode::Edit { .. }))
        {
            self.message = Some(notice);
        } else {
            self.notifications.push_back(notice);
        }
    }

    pub fn message_text(&self) -> Option<&str> {
        self.message.as_ref().map(|notice| notice.text.as_str())
    }

    pub fn acknowledge(&mut self) {
        self.message = self.notifications.pop_front();
        self.modal_scroll = 0;
        self.show_pending_approval();
    }

    pub fn offer_approval(&mut self, request: ApprovalRequest) {
        if self.completed_approvals.contains(&request.id) {
            return;
        }
        self.apply_task_status(&request);
        let procedure = super::approval_procedure(&request);
        let title = format!("Deploy {}", request.target);
        let step = request.procedure.clone();
        self.ensure_procedure(&procedure, || title, step.as_ref())
            .awaiting_deployment = false;
        if let Some(queued) = self
            .pending_approvals
            .iter_mut()
            .find(|queued| queued.id == request.id)
        {
            // A stale trust stage must not replace an already advanced final stage.
            if request.approval_stage() > queued.approval_stage()
                || (request.approval_stage() == queued.approval_stage()
                    && request.host_mutation_token == queued.host_mutation_token)
            {
                *queued = request;
            }
        } else if let Mode::Approval(current) = &mut self.mode {
            if current.id == request.id {
                if request.approval_stage() > current.approval_stage() {
                    *current = request;
                }
                return;
            }
            self.pending_approvals.push_back(request);
            self.arrive(&procedure);
        } else {
            self.pending_approvals.push_back(request);
            self.arrive(&procedure);
        }
        self.show_pending_approval();
    }

    pub fn finish_approval(&mut self, id: &str) {
        self.completed_approvals.insert(id.to_owned());
        self.pending_approvals.retain(|request| request.id != id);
        if matches!(&self.mode, Mode::Approval(request) if request.id == id) {
            self.mode = Mode::Browse;
        }
        self.tidy_procedures();
    }

    pub fn show_pending_approval(&mut self) {
        // Notices must not hide a newly arrived request. Preserve failures
        // as well as informational messages for acknowledgement afterward.
        self.tidy_procedures();
        // Only the foreground procedure's approval opens by itself; others
        // wait in the task bar until the operator restores them.
        let foreground_approval = self
            .foreground
            .as_deref()
            .filter(|id| self.procedure(id).is_some_and(|procedure| !procedure.minimised))
            .and_then(|id| {
                self.pending_approvals
                    .iter()
                    .position(|request| super::approval_procedure(request) == id)
            });
        if matches!(self.mode, Mode::Browse)
            && (!self.pending_dialogs.is_empty() || foreground_approval.is_some())
        {
            if let Some(notice) = self.message.take() {
                self.notifications.push_front(notice);
            }
            self.mode = match self.pending_dialogs.pop_front() {
                Some(dialog) => dialog,
                None => Mode::Approval(
                    self.pending_approvals
                        .remove(foreground_approval.expect("checked above"))
                        .expect("index from position"),
                ),
            };
            return;
        }
        if self.message.is_none() && matches!(self.mode, Mode::Browse) {
            self.message = self.notifications.pop_front();
        }
    }
}

impl Model {
    /// Moves a dialog scroll offset by one line, never past the last line the
    /// dialog can show. An offset from a previous, longer dialog is clamped
    /// first.
    pub fn scrolled(&self, scroll: u16, down: bool) -> u16 {
        let limit = self.scroll_limit.get();
        let scroll = scroll.min(limit);
        if down {
            scroll.saturating_add(1).min(limit)
        } else {
            scroll.saturating_sub(1)
        }
    }

    /// Whether the last line of this host-change batch is on screen now. Only
    /// a limit measured for this exact batch counts; a replacement batch is
    /// scrolled back to the top before any input reaches it.
    pub fn host_review_at_end(&self, batch: &str) -> bool {
        let limit = self.scroll_limit.get();
        let scroll = match &self.host_review {
            Some((token, _)) if token == batch => self.modal_scroll,
            _ => 0,
        };
        self.host_review_rendered.borrow().as_deref() == Some(batch)
            && limit != u16::MAX
            && scroll >= limit
    }

    /// Whether every row of this host-change batch has been displayed.
    pub fn host_review_seen(&self, batch: &str) -> bool {
        matches!(&self.host_review, Some((token, true)) if token == batch)
            || self.host_review_at_end(batch)
    }
}

impl Model {
    /// Every host of the evaluated schema, in tree order, for the deploy
    /// picker.
    pub fn deploy_hosts(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        for row in self.rows.iter().filter(|row| row.is_secret()) {
            if let Some(host) = crate::model::Attribute::Host.value(row) {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        hosts.sort();
        hosts
    }

    /// The host of the selected row: a value's host, or the host a group
    /// belongs to when all its values share one.
    pub fn selected_host(&self) -> Option<String> {
        let row = self.selected()?;
        if row.is_secret() {
            return crate::model::Attribute::Host.value(row);
        }
        let hosts = self
            .rows
            .iter()
            .filter(|candidate| {
                candidate.is_secret()
                    && candidate
                        .display_segments
                        .starts_with(&row.display_segments)
            })
            .filter_map(|candidate| crate::model::Attribute::Host.value(candidate))
            .collect::<std::collections::BTreeSet<_>>();
        (hosts.len() == 1).then(|| hosts.into_iter().next().expect("one host"))
    }

    /// `D`: opens the host picker with the selected row's host preselected.
    pub fn open_deploy_picker(&mut self) {
        let hosts = self.deploy_hosts();
        if hosts.is_empty() {
            self.inform("the evaluated schema has no hosts to deploy");
            return;
        }
        let selected = self
            .selected_host()
            .and_then(|host| hosts.iter().position(|candidate| *candidate == host))
            .unwrap_or(0);
        self.mode = Mode::DeployHost { selected };
    }
}
