use super::*;

impl Model {
    pub fn notify(&mut self, message: impl Into<String>) {
        let message = message.into();
        if self.message.as_deref() == Some(message.as_str())
            || self
                .notifications
                .back()
                .is_some_and(|queued| queued == &message)
        {
            return;
        }
        if self.message.is_none() {
            self.message = Some(message);
        } else {
            self.notifications.push_back(message);
        }
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
