use crate::ApprovalRequest;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, SyncSender};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BackendEvent {
    SecretChanged { path: String, set: bool },
    PublicInfoChanged { shared_id: String, set: bool },
    ApprovalRequested { request: ApprovalRequest },
}

#[derive(Default)]
pub(super) struct Feed {
    subscribers: Mutex<Vec<SyncSender<BackendEvent>>>,
}

impl Feed {
    pub(super) fn subscribe(&self) -> Receiver<BackendEvent> {
        let (sender, receiver) = mpsc::sync_channel(64);
        self.subscribers
            .lock()
            .expect("feed lock poisoned")
            .push(sender);
        receiver
    }

    pub(super) fn publish(&self, event: BackendEvent) {
        self.subscribers
            .lock()
            .expect("feed lock poisoned")
            .retain(|sender| sender.try_send(event.clone()).is_ok());
    }
}
