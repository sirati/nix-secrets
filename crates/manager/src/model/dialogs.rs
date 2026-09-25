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
        if self.message.is_none() {
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
        if self.message.is_none() && matches!(self.mode, Mode::Browse) {
            if let Some(dialog) = self.pending_dialogs.pop_front() {
                self.mode = dialog;
            } else if let Some(request) = self.pending_approvals.pop_front() {
                self.mode = Mode::Approval(request);
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
