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
use serde::{Deserialize, Serialize};

/// The environment variable carrying a procedure token to requesters.
pub const PROCEDURE_ENVIRONMENT: &str = "NIX_SECRETS_PROCEDURE";
pub const MAX_TITLE_BYTES: usize = 256;
pub const MAX_LABEL_BYTES: usize = 512;
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
}
