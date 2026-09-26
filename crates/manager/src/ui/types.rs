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
    /// The autosave checkbox in the value entry field.
    AutosaveToggle,
    /// The Yes button of the uncommitted-overwrite warning.
    ConfirmLoss,
    /// Reveals the stored value from an entry or replace dialog.
    RevealCurrent,
    /// The body of an informational notice; clicking it only closes it.
    Notice,
    /// The progress overlay of a running operation; clicks on it do nothing.
    Busy,
    /// The Amend checkbox of the commit dialog.
    CommitAmend,
    /// The Signoff checkbox of the commit dialog.
    CommitSignoff,
    /// Opens the commit message in the local editor.
    CommitEditor,
    /// Commits.
    CommitSubmit,
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
    Tab,
    /// Ctrl+Shift+Y: confirms overwriting a value that was never committed.
    ConfirmLoss,
    /// Ctrl+R in an entry or replace dialog: reveal the stored value.
    RevealCurrent,
    /// Ctrl+S in the commit dialog: commit.
    Submit,
    /// Ctrl+O in the commit dialog: toggle Signoff.
    ToggleSignoff,
    /// Ctrl+E in the commit dialog: edit the message in `$VISUAL`/`$EDITOR`.
    OpenEditor,
    /// The editor closed; carries the edited message, or why it failed.
    Edited(Result<String, String>),
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
    /// An operator keypair was generated and stored.
    KeypairGenerated(String),
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
    /// A deployment finished; lists values its target generated and stored.
    Deployed {
        generated: Vec<String>,
    },
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
    CommitSummary(nix_secrets_core::git::CommitSummary),
    Committed(nix_secrets_core::git::CommitResult),
    /// A commit failed; carries git's full error output.
    CommitFailed(String),
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
    /// Runs an operator leaf's keypair generator and stores the result.
    fn generate_keypair(&mut self, _path: &str) -> Result<(), String> {
        Err("keypair generation unavailable".into())
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
    /// Whether the stored value of `path` is committed in git, asked before
    /// replacing it.
    fn commit_state(&mut self, _path: &str) -> nix_secrets_core::CommitState {
        nix_secrets_core::CommitState::Unknown {
            reason: "commit state unavailable".into(),
        }
    }
    /// Asks for what a commit would contain; answered by
    /// [`Completion::CommitSummary`] or directly.
    fn commit_summary(&mut self) -> Result<nix_secrets_core::git::CommitSummary, String> {
        Err("committing is unavailable".into())
    }
    /// Commits the managed files; answered by [`Completion::Committed`] or
    /// [`Completion::CommitFailed`], or directly.
    fn commit(
        &mut self,
        _options: nix_secrets_core::git::CommitOptions,
    ) -> Result<nix_secrets_core::git::CommitResult, String> {
        Err("committing is unavailable".into())
    }
    /// The slow operation currently running in the background, if any.
    fn activity(&mut self) -> Option<crate::model::Activity> {
        None
    }
}

pub trait Frontend {
    fn draw(&mut self, model: &Model) -> io::Result<()>;
    fn read(&mut self, timeout: std::time::Duration) -> io::Result<UiEvent>;
    /// Edits `text` in the local terminal editor, suspending the interface
    /// while it runs.
    fn edit(&mut self, _text: &str) -> Result<String, String> {
        Err("no editor is available here".into())
    }
}
