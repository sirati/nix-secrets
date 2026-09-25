use super::*;
use nix_secrets_core::{ProfileSnapshot, ViewProfile};

pub const OPERATION_QUEUED: &str = "nix-secrets:operation-queued";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shortcut {
    Enter,
    Escape,
    Character(char),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MouseTarget {
    Filter(u8),
    Tree(usize),
    ModalItem(usize),
    Shortcut(Shortcut),
    /// The body of an informational notice; clicking it only closes it.
    Notice,
    /// The progress overlay of a running operation; clicks on it do nothing.
    Busy,
}

#[derive(Debug, Eq, PartialEq)]
pub enum UiEvent {
    Up,
    Down,
    Enter,
    Escape,
    Character(char),
    Backspace,
    Paste(Vec<u8>),
    /// Ctrl+V: read the clipboard directly instead of waiting for the terminal.
    PasteRequest,
    Approval(ApprovalRequest),
    Refresh,
    Tick,
    Hover(Option<MouseTarget>),
    Click(MouseTarget),
}

#[derive(Debug, Eq, PartialEq)]
pub enum Action {
    Continue,
    Quit,
    Saved(String),
    Queued,
    Approved,
    Rejected,
}

pub enum Completion {
    Saved(String),
    SaveFailed {
        path: String,
        value: Zeroizing<Vec<u8>>,
        message: String,
    },
    Deleted(String),
    Revealed {
        path: String,
        value: Zeroizing<Vec<u8>>,
    },
    Copied(String),
    Generated {
        path: String,
        value: Zeroizing<Vec<u8>>,
        replacing: bool,
    },
    BulkGenerated {
        saved: usize,
        failed: Vec<String>,
    },
    BulkProgress {
        done: usize,
        total: usize,
    },
    ApprovalDone(Option<ApprovalRequest>),
    ApprovalLost(String),
    Failed(String),
    ProfileSaved {
        name: String,
        snapshot: ProfileSnapshot,
    },
    ProfileDeleted {
        name: String,
        snapshot: ProfileSnapshot,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerateKind {
    Password,
    Passphrase,
}

pub trait SecretWriter {
    fn refresh_profiles(&mut self) -> Result<Option<ProfileSnapshot>, String> {
        Ok(None)
    }
    fn save_profile(
        &mut self,
        _name: String,
        _profile: ViewProfile,
        _revision: u64,
    ) -> Result<ProfileSnapshot, String> {
        Err("profile saving unavailable".into())
    }
    fn delete_profile(&mut self, _name: String, _revision: u64) -> Result<ProfileSnapshot, String> {
        Err("profile deletion unavailable".into())
    }
    fn poll_completion(&mut self) -> Option<Completion> {
        None
    }
    fn refresh_rows(&mut self) -> Result<Option<Vec<Row>>, String> {
        Ok(None)
    }
    fn write(
        &mut self,
        path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)>;
    fn poll_approval(&mut self) -> Result<Option<ApprovalRequest>, String> {
        Ok(None)
    }
    fn approval(&mut self, _accepted: bool) -> Result<Option<ApprovalRequest>, String> {
        Ok(None)
    }
    fn delete(&mut self, _path: &str) -> Result<(), String> {
        Err("deletion unavailable".into())
    }
    fn reveal(&mut self, _path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("reveal unavailable".into())
    }
    fn copy_public(&mut self, _path: &str) -> Result<(), String> {
        Err("public key unavailable".into())
    }
    fn generate(&mut self, _path: &str, _kind: GenerateKind) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("select a password leaf".into())
    }
    fn generate_for(
        &mut self,
        path: &str,
        kind: GenerateKind,
        _replacing: bool,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        self.generate(path, kind)
    }
    fn generate_missing(&mut self, _paths: Vec<String>, _kind: GenerateKind) -> Result<(), String> {
        Err("bulk generation unavailable".into())
    }
    fn copy(&mut self, _value: &[u8]) -> Result<(), String> {
        Err("no clipboard provider is available".into())
    }
    /// Reads the local clipboard for Ctrl+V in an entry dialog.
    fn paste(&mut self) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("no clipboard provider is available".into())
    }
    /// The slow operation currently running in the background, if any.
    fn activity(&mut self) -> Option<crate::model::Activity> {
        None
    }
}

pub trait Frontend {
    fn draw(&mut self, model: &Model) -> io::Result<()>;
    fn read(&mut self, timeout: std::time::Duration) -> io::Result<UiEvent>;
}
