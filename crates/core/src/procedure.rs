//! Procedures: a titled group of operator prompts from one logical
//! operation, such as an update run that authenticates over SSH, signs a
//! closure and then deploys secrets.
//!
//! `nix-secrets procedure --title TITLE -- COMMAND` registers a procedure
//! with the backend ([`crate::Request::BeginProcedure`]) and hands its
//! token to the command in [`PROCEDURE_ENVIRONMENT`]. Requester commands
//! that find the token send it with their request. The backend accepts it
//! only from a descendant of the process that registered the procedure,
//! numbers the request as the next step and tells the TUI which procedure
//! the prompt belongs to. The procedure ends when its registering
//! connection closes.
//!
//! `nix-secrets procedure-step-failed --label TEXT --reason TEXT` inside the
//! command reports a step as failed ([`crate::Request::FailProcedureStep`]):
//! the backend numbers it like a request, with the same token and
//! descendant checks, and the TUI shows it as a failed step with its reason.
//! `nix-secrets procedure-step-warning` reports a step that worked with a
//! caveat ([`crate::Request::WarnProcedureStep`]) the same way.
//! `nix-secrets procedure-step-progress` reports what the current step does
//! right now ([`crate::Request::ReportProcedureProgress`]); it never numbers a
//! step.
//! `nix-secrets procedure-confirm` asks the operator to confirm a risky step
//! ([`crate::Request::ConfirmProcedureStep`], [`Confirmation`]) and waits for
//! the answer; it numbers no step either.
use serde::{Deserialize, Serialize};

/// The environment variable carrying a procedure token to requesters.
pub const PROCEDURE_ENVIRONMENT: &str = "NIX_SECRETS_PROCEDURE";
pub const MAX_TITLE_BYTES: usize = 256;
pub const MAX_LABEL_BYTES: usize = 512;
/// The longest reason a requester may give for a failed or warned step.
pub const MAX_REASON_BYTES: usize = 2048;
/// The most steps a procedure may declare.
pub const MAX_DECLARED_STEPS: u32 = 1000;
/// Live procedures per backend.
pub const MAX_PROCEDURES: usize = 64;

/// Where a prompt sits in its procedure, as the backend numbered it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureStep {
    /// Public identifier; never the token.
    pub id: String,
    pub title: String,
    /// 0 while the procedure has not asked anything yet.
    pub step: u32,
    /// How many steps the procedure declared, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steps: Option<u32>,
    /// What this step does, such as "sign closure for ns1".
    pub label: String,
    /// The step is a deployment request, answered through the approval
    /// queue rather than the operator channel.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deployment: bool,
    /// The procedure's command reported this step as failed, and why; see
    /// [`crate::Request::FailProcedureStep`]. Any later step clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    /// The procedure's command reported a warning for this step, and why; see
    /// [`crate::Request::WarnProcedureStep`]. It never sets or clears
    /// `failure`; any later step clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// What the procedure's command does in this step right now, such as
    /// an upload and its percentage; see
    /// [`crate::Request::ReportProcedureProgress`]. A new step, a failure or a
    /// warning clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<StepProgress>,
}

/// The live progress of a procedure step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepProgress {
    pub text: String,
    /// 0 to 100, when the work has a known size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
}

impl ProcedureStep {
    /// Whether a prompt at this step counts down to an automatic denial:
    /// only the first step of a procedure does.
    pub fn countdown(&self) -> bool {
        self.step <= 1
    }

    /// `step 2/4` or `step 5`, when a procedure ran past its declaration.
    pub fn position(&self) -> String {
        match self.steps {
            Some(steps) if self.step <= steps => format!("step {}/{steps}", self.step),
            _ => format!("step {}", self.step),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.is_empty()
            || self.id.len() > 128
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("procedure id is invalid");
        }
        if self.title.is_empty() || self.title.len() > MAX_TITLE_BYTES {
            return Err("procedure title has an invalid length");
        }
        if self.label.len() > MAX_LABEL_BYTES {
            return Err("procedure step label is too long");
        }
        if self.steps.is_some_and(|steps| steps == 0 || steps > MAX_DECLARED_STEPS) {
            return Err("procedure step count is invalid");
        }
        if self
            .failure
            .as_ref()
            .is_some_and(|failure| failure.is_empty() || failure.len() > MAX_REASON_BYTES)
        {
            return Err("procedure step failure has an invalid length");
        }
        if self
            .warning
            .as_ref()
            .is_some_and(|warning| warning.is_empty() || warning.len() > MAX_REASON_BYTES)
        {
            return Err("procedure step warning has an invalid length");
        }
        if self.progress.as_ref().is_some_and(|progress| {
            progress.text.is_empty()
                || progress.text.len() > MAX_REASON_BYTES
                || progress.percent.is_some_and(|percent| percent > 100)
        }) {
            return Err("procedure step progress is invalid");
        }
        Ok(())
    }
}

/// Removes control characters from requester-supplied text before anyone
/// shows it, and bounds it.
pub fn clean_text(text: &str, max_bytes: usize) -> String {
    let mut cleaned = String::new();
    for character in text.chars() {
        let character = if character.is_control() { ' ' } else { character };
        if cleaned.len() + character.len_utf8() > max_bytes {
            break;
        }
        cleaned.push(character);
    }
    cleaned.trim().to_owned()
}

/// The most items one confirmation may list.
pub const MAX_CONFIRMATION_ITEMS: usize = 1000;
/// The longest item of a confirmation, such as a file name.
pub const MAX_CONFIRMATION_ITEM_BYTES: usize = 1024;

/// What `nix-secrets procedure-confirm` asks the operator to confirm: a
/// step with a risk, its reason and what it concerns, such as the dirty
/// files of a git tree. Only an explicit answer from the operator confirms
/// it; see [`crate::Request::ConfirmProcedureStep`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub label: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
}

impl Confirmation {
    /// Cleans requester-supplied text, as for any reported step, and bounds
    /// the list. The label must not be empty.
    pub fn cleaned(label: &str, reason: &str, items: &[String]) -> Result<Self, String> {
        let label = clean_text(label, MAX_LABEL_BYTES);
        if label.is_empty() {
            return Err("a confirmation needs a label".into());
        }
        if items.len() > MAX_CONFIRMATION_ITEMS {
            return Err(format!(
                "a confirmation lists at most {MAX_CONFIRMATION_ITEMS} items"
            ));
        }
        let reason = match clean_text(reason, MAX_REASON_BYTES) {
            reason if reason.is_empty() => "no reason given".to_owned(),
            reason => reason,
        };
        let items = items
            .iter()
            .map(|item| clean_text(item, MAX_CONFIRMATION_ITEM_BYTES))
            .filter(|item| !item.is_empty())
            .collect();
        Ok(Self {
            label,
            reason,
            items,
        })
    }

    /// Whether it is as [`Self::cleaned`] leaves it; the TUI shows nothing
    /// else.
    pub fn validate(&self) -> Result<(), &'static str> {
        let clean = |text: &str, max: usize| {
            !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
        };
        if !clean(&self.label, MAX_LABEL_BYTES)
            || !clean(&self.reason, MAX_REASON_BYTES)
            || self.items.len() > MAX_CONFIRMATION_ITEMS
            || !self
                .items
                .iter()
                .all(|item| clean(item, MAX_CONFIRMATION_ITEM_BYTES))
        {
            return Err("the confirmation is malformed");
        }
        Ok(())
    }
}

/// Splits a token into its public id and its secret part.
pub fn split_token(token: &str) -> Option<(&str, &str)> {
    let (id, secret) = token.split_once(':')?;
    (!id.is_empty() && !secret.is_empty()).then_some((id, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_first_step_counts_down_and_positions_read_naturally() {
        let mut step = ProcedureStep {
            id: "proc-1".into(),
            title: "Update ns1".into(),
            step: 1,
            steps: Some(4),
            label: "sign closure".into(),
            deployment: false,
            failure: None,
            warning: None,
            progress: None,
        };
        assert!(step.countdown());
        assert_eq!(step.position(), "step 1/4");
        step.step = 2;
        assert!(!step.countdown());
        assert_eq!(step.position(), "step 2/4");
        step.step = 5;
        assert_eq!(step.position(), "step 5");
        step.steps = None;
        assert_eq!(step.position(), "step 5");
        assert!(step.validate().is_ok());
        step.failure = Some("rolled back".into());
        assert!(step.validate().is_ok());
        step.failure = Some(String::new());
        assert!(step.validate().is_err());
        step.failure = Some("x".repeat(MAX_REASON_BYTES + 1));
        assert!(step.validate().is_err());
        step.failure = None;
        step.warning = Some("units already failed before".into());
        assert!(step.validate().is_ok());
        step.warning = Some(String::new());
        assert!(step.validate().is_err());
        step.warning = Some("x".repeat(MAX_REASON_BYTES + 1));
        assert!(step.validate().is_err());
        step.warning = None;
        step.progress = Some(StepProgress { text: "uploading".into(), percent: Some(100) });
        assert!(step.validate().is_ok());
        step.progress = Some(StepProgress { text: "uploading".into(), percent: Some(101) });
        assert!(step.validate().is_err());
        step.progress = Some(StepProgress { text: String::new(), percent: None });
        assert!(step.validate().is_err());
        step.progress = None;
        step.id = "proc:1".into();
        assert!(step.validate().is_err());
    }

    #[test]
    fn requester_text_loses_control_characters_and_is_bounded() {
        assert_eq!(clean_text("Update\x1b]2;x\x07 ns1\n", 64), "Update ]2;x  ns1");
        assert_eq!(clean_text("ääää", 5).len(), 4);
        assert_eq!(split_token("proc-1:abc"), Some(("proc-1", "abc")));
        assert_eq!(split_token("proc-1:"), None);
        assert_eq!(split_token("nocolon"), None);
    }

    #[test]
    fn confirmations_are_cleaned_bounded_and_validated() {
        let confirmation = Confirmation::cleaned(
            " deployed from a dirty tree\x07",
            "",
            &["M flake.nix".into(), "\x1b[2J".into(), " ?? new.nix ".into()],
        )
        .unwrap();
        assert_eq!(confirmation.label, "deployed from a dirty tree");
        assert_eq!(confirmation.reason, "no reason given");
        assert_eq!(confirmation.items, ["M flake.nix", "[2J", "?? new.nix"]);
        assert!(confirmation.validate().is_ok());
        assert!(Confirmation::cleaned(" \x07 ", "r", &[]).is_err());
        let many = vec!["x".to_owned(); MAX_CONFIRMATION_ITEMS + 1];
        assert!(Confirmation::cleaned("l", "r", &many).is_err());
        let long = Confirmation::cleaned("l", "r", &["y".repeat(5000)]).unwrap();
        assert_eq!(long.items[0].len(), MAX_CONFIRMATION_ITEM_BYTES);
        let mut bad = confirmation.clone();
        bad.items.push("a\nb".into());
        assert!(bad.validate().is_err());
        let mut bad = confirmation;
        bad.label.clear();
        assert!(bad.validate().is_err());
    }
}
