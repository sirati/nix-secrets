use crate::tree::{Row, RowCategory};
use std::collections::VecDeque;
use zeroize::Zeroizing;

mod attributes;
mod catalog;
mod collapse;
mod dialogs;
mod procedures;
mod profiles;
mod visibility;
pub use procedures::{approval_procedure, prompt_procedure, Procedure, FLASH_PERIOD};
pub use attributes::{Attribute, Facet, FacetMode};
use std::collections::BTreeMap;
pub use visibility::SearchSummary;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoticeSeverity {
    /// Success or guidance: the next key or click closes it and still acts.
    Info,
    /// An operation failed: only an explicit OK closes it.
    Failure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notice {
    pub text: String,
    pub severity: NoticeSeverity,
}

/// Public fingerprints and purposes for an exact host-provided replacement batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostMutationReview {
    pub identifier: String,
    pub kind: String,
    pub previous: Vec<String>,
    pub proposed: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApprovalRequest {
    pub id: String,
    pub target: String,
    pub host_mutations: Vec<HostMutationReview>,
    pub host_mutations_before_deploy: bool,
    pub connection_warnings: Vec<String>,
    /// Identifies the immutable batch shown here; ordinary deploy consent cannot save it.
    pub host_mutation_token: Option<String>,
    pub create: Vec<String>,
    pub replace: Vec<String>,
    pub recipient_keys: Vec<String>,
    pub host_key: Option<String>,
    pub tasks: Vec<TaskApproval>,
    /// Unset values the target will generate, with the generator label.
    pub generate: Vec<(String, String)>,
    /// Unset values nobody can generate. A deployment with any of them is
    /// refused before anything is generated or written.
    pub missing: Vec<(String, String)>,
    /// Values deployed from another secret: (identifier, source).
    pub derived: Vec<(String, String)>,
    /// Values in `missing` a partial deployment leaves out.
    pub skippable: Vec<String>,
    /// The group of each missing value, such as "Needs input".
    pub missing_kinds: std::collections::BTreeMap<String, String>,
    /// Unset public information the host installs its own default for.
    pub host_default: Vec<String>,
    /// The operator chose to deploy without the `skippable` values.
    pub allow_partial: bool,
    /// The key the deployment's SSH login signs with, named.
    pub login_key: Option<Box<str>>,
    /// Rows the operator unchecked; they are not sent.
    pub unchecked: std::collections::BTreeSet<String>,
    /// The row the cursor is on, among the rows with a checkbox.
    pub cursor: usize,
    /// The procedure step the backend assigned, if the request is part of
    /// a procedure.
    pub procedure: Option<nix_secrets_core::procedure::ProcedureStep>,
}

impl ApprovalRequest {
    pub(crate) fn approval_stage(&self) -> u8 {
        if !self.host_mutations.is_empty() {
            if self.host_mutations_before_deploy { 1 } else { 3 }
        } else if self.host_key.is_some() { 0 } else { 2 }
    }

    /// Whether a partial deployment can proceed: something is missing and
    /// every missing value waits for another host.
    pub fn partial_possible(&self) -> bool {
        !self.missing.is_empty()
            && self
                .missing
                .iter()
                .all(|(identifier, _)| self.skippable.contains(identifier))
    }

    /// Whether approving deploys anything. Missing values never block; only
    /// a request with nothing deployable is refused.
    pub fn deployable(&self) -> bool {
        !self.checked().is_empty()
    }
}

/// A section of the deployment dialog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Section {
    /// Values the operator's machine sends: set, replaced, derived, public
    /// information and target tasks.
    Sent,
    /// Values the target generates and returns as ciphertext.
    Generated,
}

/// One row with a checkbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployRow {
    pub section: Section,
    pub identifier: String,
    /// What happens to it, such as "set", "replaced", "from <source>".
    pub what: String,
}

impl ApprovalRequest {
    /// The rows with a checkbox, in display order: "Will be sent", then
    /// "Will be generated". Missing values have none.
    pub fn rows(&self) -> Vec<DeployRow> {
        if !self.host_mutations.is_empty() {
            return Vec::new();
        }
        let missing = |identifier: &String| self.missing.iter().any(|(id, _)| id == identifier);
        let generated = |identifier: &String| self.generate.iter().any(|(id, _)| id == identifier);
        let derived = |identifier: &String| self.derived.iter().any(|(id, _)| id == identifier);
        let mut rows = Vec::new();
        let mut sent = |identifier: &String, what: String| {
            rows.push(DeployRow {
                section: Section::Sent,
                identifier: identifier.clone(),
                what,
            })
        };
        for (identifier, what) in self
            .create
            .iter()
            .map(|id| (id, "set"))
            .chain(self.replace.iter().map(|id| (id, "replaced")))
        {
            if !missing(identifier) && !generated(identifier) && !derived(identifier) {
                sent(identifier, what.to_owned());
            }
        }
        for (identifier, source) in &self.derived {
            if !missing(identifier) {
                sent(identifier, format!("derived from {source}"));
            }
        }
        for task in &self.tasks {
            if !missing(&task.identifier) {
                sent(&task.identifier, task_what(task));
            }
        }
        for (identifier, kind) in &self.generate {
            rows.push(DeployRow {
                section: Section::Generated,
                identifier: identifier.clone(),
                what: kind.clone(),
            });
        }
        rows
    }

    /// The rows that are checked: what approving sends or generates.
    pub fn checked(&self) -> Vec<DeployRow> {
        self.rows()
            .into_iter()
            .filter(|row| !self.unchecked.contains(&row.identifier))
            .collect()
    }

    /// Toggles one row.
    pub fn toggle(&mut self, identifier: &str) {
        if !self.unchecked.remove(identifier) {
            self.unchecked.insert(identifier.to_owned());
        }
    }

    /// Toggles a whole section: all checked unless every row already is.
    pub fn toggle_section(&mut self, section: Section) {
        let rows = self
            .rows()
            .into_iter()
            .filter(|row| row.section == section)
            .map(|row| row.identifier)
            .collect::<Vec<_>>();
        if rows.iter().all(|row| !self.unchecked.contains(row)) {
            self.unchecked.extend(rows);
        } else {
            for row in rows {
                self.unchecked.remove(&row);
            }
        }
    }
}

fn task_what(task: &TaskApproval) -> String {
    let output = match task.output_is_set {
        Some(true) => "installed",
        Some(false) => "not installed",
        None => "unknown",
    };
    if task.requires_input {
        format!("target task; its key {output}")
    } else {
        format!("generated on the target; its key {output}")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskApproval {
    pub identifier: String,
    pub input_is_set: bool,
    pub output_is_set: Option<bool>,
    pub requires_input: bool,
}

/// Client-side preferences for this session only. They reset on restart and
/// are never written to the repository or to profiles. To add a setting, add
/// a field and a line to [`Settings::ITEMS`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Settings {
    /// A paste into the entry field of an unset value saves it at once.
    pub autosave_unset_on_paste: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Setting {
    AutosaveUnsetOnPaste,
}

impl Settings {
    pub const ITEMS: [Setting; 1] = [Setting::AutosaveUnsetOnPaste];

    pub fn get(&self, setting: Setting) -> bool {
        match setting {
            Setting::AutosaveUnsetOnPaste => self.autosave_unset_on_paste,
        }
    }

    pub fn toggle(&mut self, setting: Setting) {
        match setting {
            Setting::AutosaveUnsetOnPaste => {
                self.autosave_unset_on_paste = !self.autosave_unset_on_paste
            }
        }
    }
}

impl Setting {
    pub fn label(self) -> &'static str {
        match self {
            Self::AutosaveUnsetOnPaste => "Autosave unset values on paste",
        }
    }
}

// One Mode lives at a time; boxing the approval would touch every match on
// it for a few hundred bytes.
#[allow(clippy::large_enum_variant)]
#[derive(Eq, PartialEq)]
pub enum Mode {
    Browse,
    Settings {
        selected: usize,
    },
    Properties {
        scroll: u16,
    },
    FacetCategories {
        selected: usize,
    },
    FacetValues {
        attribute: Attribute,
        selected: usize,
    },
    FacetFirstChoice {
        attribute: Attribute,
        value: String,
    },
    TreeOrder {
        selected: usize,
    },
    Profiles {
        selected: usize,
    },
    ProfileSave {
        name: String,
    },
    ProfileOverwrite {
        name: String,
    },
    ProfileDelete {
        name: String,
    },
    Help {
        scroll: u16,
    },
    Search {
        query: String,
    },
    DeleteConfirm {
        path: String,
        /// Whether the value being deleted is committed in git; if not, the
        /// dialog is the loss warning of [`Mode::Replace`].
        commit: nix_secrets_core::CommitState,
    },
    Reveal {
        path: String,
        value: Zeroizing<Vec<u8>>,
        scroll: u16,
        /// The entry or replace dialog the reveal was opened from; closing the
        /// reveal returns there with its typed value.
        underneath: Option<Box<Mode>>,
    },
    Edit {
        path: String,
        value: Zeroizing<Vec<u8>>,
    },
    Replace {
        path: String,
        value: Zeroizing<Vec<u8>>,
        /// Whether the value being replaced is committed in git.
        commit: nix_secrets_core::CommitState,
    },
    GenerateChoice {
        path: String,
        replacing: bool,
    },
    /// Confirms running an operator leaf's declared keypair generator.
    KeypairConfirm {
        path: String,
        replacing: bool,
    },
    BulkGenerateConfirm {
        paths: Vec<String>,
    },
    BulkProgress {
        total: usize,
        done: usize,
    },
    GeneratedPreview {
        path: String,
        value: Zeroizing<Vec<u8>>,
        revealed: bool,
        replacing: bool,
    },
    Approval(ApprovalRequest),
    /// Picks the host to deploy; see [`Model::deploy_hosts`].
    DeployHost {
        selected: usize,
    },
    /// The Git Commit dialog.
    Commit {
        draft: CommitDraft,
        summary: nix_secrets_core::git::CommitSummary,
        /// Set by Ctrl+E: the frontend opens the message in an editor.
        editing: bool,
    },
    ProviderFailure {
        message: String,
        path: String,
        value: Zeroizing<Vec<u8>>,
    },
}

mod debug;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Activity {
    /// For example `Decrypting host.services.x.y`.
    pub label: String,
    /// Whether the step may wait for a 1Password authorization prompt.
    pub waits_for_one_password: bool,
    pub started: std::time::Instant,
}

pub struct Model {
    pub rows: Vec<Row>,
    pub selected: usize,
    pub mode: Mode,
    pub message: Option<Notice>,
    pub modal_scroll: u16,
    /// The furthest the open dialog can scroll, recorded by the last render.
    pub scroll_limit: std::cell::Cell<u16>,
    /// The host-change review batch on screen and whether its last line has
    /// been displayed. Saving requires the whole batch to have been seen.
    pub host_review: Option<(String, bool)>,
    /// The review batch whose height `scroll_limit` was measured for.
    pub host_review_rendered: std::cell::RefCell<Option<String>>,
    pub hover: Option<crate::ui::MouseTarget>,
    pub notifications: VecDeque<Notice>,
    pub pending_approvals: VecDeque<ApprovalRequest>,
    /// Terminal IDs stay suppressed for this frontend session, including late events.
    completed_approvals: std::collections::BTreeSet<String>,
    pub pending_dialogs: VecDeque<Mode>,
    pub filter: ViewFilter,
    pub human_only: bool,
    pub search: String,
    pub tree_order: Vec<Attribute>,
    pub facets: BTreeMap<Attribute, Facet>,
    pub profiles: nix_secrets_core::ProfileSnapshot,
    pub active_profile: Option<String>,
    /// The slow background operation in progress, shown as an overlay.
    pub activity: Option<Activity>,
    pub settings: Settings,
    /// The commit message and options last typed, kept until a commit
    /// succeeds so a cancelled or failed commit can be resumed.
    pub commit_draft: CommitDraft,
    /// Collapsed groups by their path of attribute values; see `collapse`.
    pub collapsed: std::collections::BTreeSet<Vec<String>>,
    /// Groups folded during a search, with the query they belong to.
    pub search_collapsed: (String, std::collections::BTreeSet<Vec<String>>),
    /// Procedures with prompts, in task bar order; see `procedures`.
    pub procedures: Vec<Procedure>,
    /// The procedure whose dialog is on screen, if any.
    pub foreground: Option<String>,
    /// The phase of flashing task bar entries.
    pub flash_on: bool,
    pub flash_since: std::time::Instant,
    pub secret_scroll: u16,
    /// Whether the secret-request modal shows full commands, fingerprints
    /// and descriptions instead of its summary.
    pub secret_details: bool,
    /// The deployment dialog shows every identifier and reason (`d`).
    pub approval_details: bool,
}

pub struct VisibleRow {
    pub index: usize,
    pub depth: usize,
    pub label: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewFilter {
    Required,
    All,
    Keys,
    Passwords,
    PublicInfo,
}

impl ViewFilter {
    pub fn next(self) -> Self {
        match self {
            Self::Required => Self::All,
            Self::All => Self::Keys,
            Self::Keys => Self::Passwords,
            Self::Passwords => Self::PublicInfo,
            Self::PublicInfo => Self::Required,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Required => "operator input",
            Self::All => "all",
            Self::Keys => "keys",
            Self::Passwords => "passwords",
            Self::PublicInfo => "public info",
        }
    }
}

impl Model {
    pub fn update_rows(&mut self, rows: Vec<Row>) {
        let identity = self.selection_identity();
        let was_value = identity
            .as_ref()
            .is_some_and(|identity| identity.is_value());
        self.rows = rows;
        self.rebuild_tree();
        if !self.restore_selection(identity) {
            self.selected = if was_value {
                0
            } else {
                self.selected
                    .min(self.visible_rows().len().saturating_sub(1))
            };
        }
    }
    pub fn new(rows: Vec<Row>) -> Self {
        let structured = rows.iter().any(|row| row.identity.is_some());
        let mut model = Self {
            rows,
            selected: 0,
            mode: Mode::Browse,
            message: None,
            modal_scroll: 0,
            scroll_limit: std::cell::Cell::new(u16::MAX),
            host_review: None,
            host_review_rendered: Default::default(),
            hover: None,
            notifications: VecDeque::new(),
            pending_approvals: VecDeque::new(),
            completed_approvals: Default::default(),
            pending_dialogs: VecDeque::new(),
            filter: ViewFilter::Required,
            human_only: false,
            search: String::new(),
            tree_order: Attribute::DEFAULT_TREE.to_vec(),
            facets: BTreeMap::new(),
            profiles: nix_secrets_core::ProfileSnapshot::default(),
            active_profile: None,
            activity: None,
            settings: Settings::default(),
            commit_draft: CommitDraft::default(),
            collapsed: Default::default(),
            search_collapsed: Default::default(),
            procedures: Vec::new(),
            foreground: None,
            flash_on: false,
            flash_since: std::time::Instant::now(),
            secret_scroll: 0,
            secret_details: false,
            approval_details: false,
        };
        if structured {
            model.rebuild_tree();
        }
        model
    }

    pub fn selected(&self) -> Option<&Row> {
        self.visible_rows()
            .get(self.selected)
            .and_then(|index| self.rows.get(*index))
    }

    pub fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.selected = 0;
    }
    pub fn set_filter(&mut self, filter: ViewFilter) {
        self.filter = filter;
        self.selected = 0;
    }

    pub fn set_human_only(&mut self, enabled: bool) {
        self.human_only = enabled;
        self.selected = 0;
    }

    pub fn toggle_human(&mut self) {
        self.human_only = !self.human_only;
        self.selected = 0;
    }

    pub fn move_by(&mut self, amount: isize) {
        let count = self.visible_rows().len();
        if count == 0 {
            return;
        }
        self.selected = self.selected.saturating_add_signed(amount).min(count - 1);
    }

    /// Opens the entry field for the selected value. Replacing a set value is
    /// confirmed only when the new value is submitted.
    pub fn begin_value(&mut self, value: Vec<u8>) {
        let Some(row) = self.selected().filter(|row| row.is_secret()) else {
            return;
        };
        let path = row.path.clone().expect("secret row has path");
        self.mode = Mode::Edit {
            path,
            value: Zeroizing::new(value),
        };
    }

    /// Whether the value at `path` is stored, so saving over it needs a
    /// confirmation.
    pub fn is_set(&self, path: &str) -> bool {
        self.rows
            .iter()
            .any(|row| row.path.as_deref() == Some(path) && row.is_set)
    }

    pub fn mark_saved(&mut self, path: &str) {
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|row| row.path.as_deref() == Some(path))
        {
            row.is_set = true;
        }
        self.mode = Mode::Browse;
        self.inform(format!("saved {path}"));
    }

    pub fn mark_deleted(&mut self, path: &str) {
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|row| row.path.as_deref() == Some(path))
        {
            row.is_set = false;
        }
        self.mode = Mode::Browse;
        self.inform(format!("deleted {path}"));
    }

    pub fn apply_task_status(&mut self, request: &ApprovalRequest) {
        for task in &request.tasks {
            if let Some(row) = self
                .rows
                .iter_mut()
                .find(|row| row.path.as_deref() == Some(&task.identifier))
            {
                row.is_set = task.input_is_set;
                row.output_is_set = task.output_is_set;
            }
        }
    }
}

#[cfg(test)]
mod facet_tests;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitDraft {
    pub message: String,
    pub amend: bool,
    pub signoff: bool,
}

/// A process from a secret request, for display.
pub struct ProcessDisplay<'a>(pub &'a nix_secrets_core::secret_request::ProcessInfo);

/// What a finished deployment did, counted, for its result notice.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeploySummary {
    pub target: String,
    pub sent: usize,
    pub generated: usize,
    /// Rows the operator unchecked.
    pub left_out: Vec<String>,
    /// Values that could not be deployed, with why.
    pub missing: Vec<String>,
}
