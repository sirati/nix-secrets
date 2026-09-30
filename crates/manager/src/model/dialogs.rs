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
        if self.message.is_none() && !matches!(self.mode, Mode::Approval(_)) {
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
        self.apply_task_status(&request);
        self.pending_approvals.push_back(request);
        self.show_pending_approval();
    }

    pub fn show_pending_approval(&mut self) {
        // Passive notices must not hide a newly arrived approval. Preserve
        // their order and restore them after the request has been answered.
        if matches!(self.mode, Mode::Browse)
            && !self.pending_approvals.is_empty()
            && self.pending_dialogs.is_empty()
            && self.message.as_ref().is_none_or(|notice| notice.severity == NoticeSeverity::Info)
        {
            if let Some(notice) = self.message.take() {
                self.notifications.push_front(notice);
            }
            self.mode = Mode::Approval(self.pending_approvals.pop_front().unwrap());
            return;
        }
        if self.message.is_none() && matches!(self.mode, Mode::Browse) {
            if let Some(dialog) = self.pending_dialogs.pop_front() {
                self.mode = dialog;
            } else if let Some(request) = self.pending_approvals.pop_front() {
                self.mode = Mode::Approval(request);
            } else {
                self.message = self.notifications.pop_front();
            }
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
                    && candidate.display_segments.starts_with(&row.display_segments)
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
