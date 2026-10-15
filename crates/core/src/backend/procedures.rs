//! The live procedures of this backend; see [`crate::procedure`].
//!
//! A procedure belongs to the process that registered it. Its token is an
//! unguessable secret, and the backend accepts it only from that process or
//! one of its descendants, as the kernel reports the peer of the requesting
//! connection. A process that learned a token some other way still cannot
//! join a procedure it does not descend from.
use super::{Request, Response};
use crate::framing::{read_json, write_json};
use crate::procedure::{
    MAX_DECLARED_STEPS, MAX_LABEL_BYTES, MAX_PROCEDURES, MAX_REASON_BYTES, MAX_TITLE_BYTES,
    ProcedureStep, StepProgress,
    clean_text, split_token,
};
use crate::secret_request::is_same_or_descendant;
use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

struct Live {
    secret: String,
    /// The registering process; requesters must descend from it.
    owner: u32,
    step: ProcedureStep,
    /// The current step may take more than one request; see
    /// [`Procedures::next_step`].
    repeatable: bool,
}

#[derive(Default)]
pub(super) struct Procedures {
    live: Mutex<BTreeMap<String, Live>>,
    next: AtomicU64,
}

/// What the procedure's command reported about a step.
enum Report {
    Failure(String),
    Warning(String),
}

/// The cleaned reason of a report; its label must not be empty.
fn reported(label: &str, reason: &str) -> Result<String, String> {
    if clean_text(label, MAX_LABEL_BYTES).is_empty() {
        return Err("a reported step needs a label".into());
    }
    let reason = clean_text(reason, MAX_REASON_BYTES);
    Ok(if reason.is_empty() {
        "no reason given".to_owned()
    } else {
        reason
    })
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut random = vec![0_u8; bytes];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Compares secrets in time independent of where they differ.
fn same_secret(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

impl Procedures {
    /// Registers a procedure of `owner`; returns its first state and token.
    pub(super) fn begin(
        &self,
        owner: u32,
        title: &str,
        steps: Option<u32>,
    ) -> Result<(ProcedureStep, String), String> {
        let title = clean_text(title, MAX_TITLE_BYTES);
        if title.is_empty() {
            return Err("a procedure needs a title".into());
        }
        if steps.is_some_and(|steps| steps == 0 || steps > MAX_DECLARED_STEPS) {
            return Err(format!(
                "a procedure declares between 1 and {MAX_DECLARED_STEPS} steps"
            ));
        }
        let mut live = self.live.lock().map_err(|_| "procedure registry poisoned")?;
        if live.len() >= MAX_PROCEDURES {
            return Err("too many procedures are running; retry when one ends".into());
        }
        let id = format!(
            "proc-{}-{}",
            self.next.fetch_add(1, Ordering::Relaxed),
            random_hex(6)?
        );
        let secret = random_hex(32)?;
        let step = ProcedureStep {
            id: id.clone(),
            title,
            step: 0,
            steps,
            label: "starting".into(),
            deployment: false,
            failure: None,
            warning: None,
            progress: None,
        };
        live.insert(
            id.clone(),
            Live {
                secret: secret.clone(),
                owner,
                step: step.clone(),
                repeatable: false,
            },
        );
        Ok((step, format!("{id}:{secret}")))
    }

    pub(super) fn end(&self, id: &str) {
        if let Ok(mut live) = self.live.lock() {
            live.remove(id);
        }
    }

    pub(super) fn snapshot(&self) -> Vec<ProcedureStep> {
        self.live
            .lock()
            .map(|live| live.values().map(|live| live.step.clone()).collect())
            .unwrap_or_default()
    }

    /// Verifies that `peer` may act in the procedure of `token` and numbers
    /// its request as the next step.
    ///
    /// A `repeatable` request with the same label as the repeatable step
    /// before it stays on that step: an SSH login to one destination is one
    /// step however many connections it takes, so a declared total stays
    /// right when a requester reconnects.
    pub(super) fn next_step(
        &self,
        token: &str,
        peer: u32,
        label: &str,
        deployment: bool,
        repeatable: bool,
    ) -> Result<ProcedureStep, String> {
        self.number_step(token, peer, label, deployment, repeatable, None)
    }

    /// Records that the step `label` failed, numbered like a repeatable
    /// request: a report about the same step again (say "rolling back",
    /// then "rolled back") updates that step instead of adding one.
    pub(super) fn fail_step(
        &self,
        token: &str,
        peer: u32,
        label: &str,
        reason: &str,
    ) -> Result<ProcedureStep, String> {
        let reason = reported(label, reason)?;
        self.number_step(token, peer, label, false, true, Some(Report::Failure(reason)))
    }

    /// Records a warning for the step `label`, numbered like
    /// [`Self::fail_step`]. On the same step it leaves `failure` alone.
    pub(super) fn warn_step(
        &self,
        token: &str,
        peer: u32,
        label: &str,
        reason: &str,
    ) -> Result<ProcedureStep, String> {
        let reason = reported(label, reason)?;
        self.number_step(token, peer, label, false, true, Some(Report::Warning(reason)))
    }

    /// Sets what the current step does right now; see
    /// [`super::Request::ReportProcedureProgress`]. The step keeps its number,
    /// label, failure and warning.
    pub(super) fn progress_step(
        &self,
        token: &str,
        peer: u32,
        text: &str,
        percent: Option<u8>,
    ) -> Result<ProcedureStep, String> {
        let text = clean_text(text, MAX_REASON_BYTES);
        if text.is_empty() {
            return Err("a progress report needs a text".into());
        }
        if percent.is_some_and(|percent| percent > 100) {
            return Err("a progress percentage is at most 100".into());
        }
        self.joined(token, peer, |procedure| {
            procedure.step.progress = Some(StepProgress { text, percent });
            procedure.step.clone()
        })
    }

    /// Runs `change` on the procedure of `token` once `peer` may act in it.
    fn joined<T>(
        &self,
        token: &str,
        peer: u32,
        change: impl FnOnce(&mut Live) -> T,
    ) -> Result<T, String> {
        let (id, secret) = split_token(token).ok_or("the procedure token is malformed")?;
        let mut live = self.live.lock().map_err(|_| "procedure registry poisoned")?;
        let procedure = live
            .get_mut(id)
            .filter(|procedure| same_secret(&procedure.secret, secret))
            .ok_or("the procedure has ended or the token is wrong")?;
        if !is_same_or_descendant(peer, procedure.owner) {
            return Err(format!(
                "this process does not belong to procedure {id}; only the command started by \
                 `nix-secrets procedure` and its descendants may join it"
            ));
        }
        Ok(change(procedure))
    }

    fn number_step(
        &self,
        token: &str,
        peer: u32,
        label: &str,
        deployment: bool,
        repeatable: bool,
        report: Option<Report>,
    ) -> Result<ProcedureStep, String> {
        let label = clean_text(label, MAX_LABEL_BYTES);
        self.joined(token, peer, |procedure| {
            let repeat = repeatable
                && procedure.repeatable
                && procedure.step.step > 0
                && procedure.step.label == label;
            if !repeat {
                procedure.step.step = procedure.step.step.saturating_add(1);
                procedure.step.failure = None;
                procedure.step.warning = None;
                procedure.step.progress = None;
            }
            procedure.step.label = label;
            procedure.step.deployment = deployment;
            match report {
                Some(Report::Failure(reason)) => {
                    procedure.step.failure = Some(reason);
                    procedure.step.progress = None;
                }
                Some(Report::Warning(reason)) => {
                    procedure.step.warning = Some(reason);
                    procedure.step.progress = None;
                }
                None => {
                    procedure.step.failure = None;
                    procedure.step.warning = None;
                }
            }
            procedure.repeatable = repeatable;
            procedure.step.clone()
        })
    }
}

/// Serves [`Request::BeginProcedure`]: the procedure lives as long as this
/// connection, which carries nothing else.
pub(super) fn serve(
    stream: &mut UnixStream,
    operators: &super::secrets::Operators,
    peer: u32,
    title: String,
    steps: Option<u32>,
) -> io::Result<()> {
    let (step, token) = match operators.procedures.begin(peer, &title, steps) {
        Ok(begun) => begun,
        Err(message) => return write_json(stream, &Response::Error { message }),
    };
    let id = step.id.clone();
    operators.broadcast_step(step);
    // How its command exited, if the owner said so before closing.
    let mut exit = None;
    let result = (|| {
        write_json(
            stream,
            &Response::ProcedureBegun {
                id: id.clone(),
                token,
            },
        )?;
        loop {
            match read_json::<Request>(stream) {
                Ok(Some(Request::EndProcedure { exit_code })) => {
                    exit = exit_code;
                    return write_json(
                        stream,
                        &Response::ProcedureEnded {
                            id: id.clone(),
                            exit_code,
                        },
                    );
                }
                Ok(Some(_)) => {
                    write_json(
                        stream,
                        &Response::Error {
                            message: "a procedure connection only ends the procedure".into(),
                        },
                    )?;
                }
                Ok(None) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    })();
    operators.procedures.end(&id);
    operators.broadcast_end(&id, exit);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_descendants_of_the_owner_with_the_exact_token_join() {
        let procedures = Procedures::default();
        let own = std::process::id();
        let (first, token) = procedures.begin(own, "Update\x07 ns1", Some(3)).unwrap();
        assert_eq!(first.title, "Update  ns1");
        assert_eq!(first.step, 0);
        let step = procedures
            .next_step(&token, own, "sign closure for ns1", false, false)
            .unwrap();
        assert_eq!((step.step, step.label.as_str()), (1, "sign closure for ns1"));
        // A descendant joins as the next step.
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let step = procedures
            .next_step(&token, child.id(), "deploy secrets to ns1", true, false)
            .unwrap();
        assert_eq!(step.step, 2);
        assert!(step.deployment);
        // A process that does not descend from the owner is refused, even
        // with the right token.
        let (_, foreign) = procedures.begin(child.id(), "Other", None).unwrap();
        let error = procedures.next_step(&foreign, own, "x", false, false).unwrap_err();
        assert!(error.contains("does not belong"), "{error}");
        child.kill().unwrap();
        child.wait().unwrap();
        // A wrong secret is refused like an unknown procedure.
        let (id, _) = split_token(&token).unwrap();
        let forged = format!("{id}:{}", "0".repeat(64));
        assert!(procedures.next_step(&forged, own, "x", false, false).is_err());
        assert!(procedures.next_step("garbage", own, "x", false, false).is_err());
        procedures.end(id);
        assert!(procedures.next_step(&token, own, "x", false, false).is_err());
        assert_eq!(procedures.snapshot().len(), 1);
    }

    #[test]
    fn repeated_logins_to_one_destination_stay_one_step() {
        let procedures = Procedures::default();
        let own = std::process::id();
        let (_, token) = procedures.begin(own, "Update ns1", Some(3)).unwrap();
        let next = |label: &str, repeatable| {
            procedures
                .next_step(&token, own, label, false, repeatable)
                .unwrap()
                .step
        };
        assert_eq!(next("sign artifacts for ns1", false), 1);
        // Not repeatable: the same label again is a new step.
        assert_eq!(next("sign artifacts for ns1", false), 2);
        assert_eq!(next("SSH authentication to update@ns1", true), 3);
        // The upload and every reconnect while waiting for the reboot.
        assert_eq!(next("SSH authentication to update@ns1", true), 3);
        assert_eq!(next("SSH authentication to update@ns1", true), 3);
        // Another destination is another step.
        assert_eq!(next("SSH authentication to update@ns2", true), 4);
        assert_eq!(next("deploy secrets to ns1", false), 5);
        // A login after something else is a new step again.
        assert_eq!(next("SSH authentication to update@ns2", true), 6);
    }

    #[test]
    fn a_failed_step_is_numbered_checked_updated_and_cleared() {
        let procedures = Procedures::default();
        let own = std::process::id();
        let (_, token) = procedures.begin(own, "Update ns1", Some(4)).unwrap();
        let step = procedures
            .next_step(&token, own, "sign closure for ns1", false, false)
            .unwrap();
        assert_eq!((step.step, step.failure), (1, None));
        let failed = procedures
            .fail_step(&token, own, "activate ns1", "failed\x1b[2J, rolling back")
            .unwrap();
        assert_eq!((failed.step, failed.label.as_str()), (2, "activate ns1"));
        assert_eq!(failed.failure.as_deref(), Some("failed [2J, rolling back"));
        assert!(failed.validate().is_ok());
        // The same step reported again updates its reason in place.
        let again = procedures
            .fail_step(&token, own, "activate ns1", "rolled back and verified")
            .unwrap();
        assert_eq!(again.step, 2);
        assert_eq!(again.failure.as_deref(), Some("rolled back and verified"));
        assert_eq!(procedures.snapshot()[0].failure.as_deref(), Some("rolled back and verified"));
        // The reason is bounded.
        let long = procedures
            .fail_step(&token, own, "activate ns1", &"x".repeat(3 * MAX_REASON_BYTES))
            .unwrap();
        assert_eq!(long.failure.unwrap().len(), MAX_REASON_BYTES);
        // Another step reported failed is a new step.
        assert_eq!(procedures.fail_step(&token, own, "activate ns2", "x").unwrap().step, 3);
        // A later normal step clears the failure.
        let next = procedures
            .next_step(&token, own, "deploy secrets to ns1", true, false)
            .unwrap();
        assert_eq!((next.step, next.failure), (4, None));
        assert!(procedures.fail_step(&token, own, " \x07 ", "x").is_err(), "empty label");
        // The token and descendant checks hold as for any request.
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let (_, foreign) = procedures.begin(child.id(), "Other", None).unwrap();
        let error = procedures.fail_step(&foreign, own, "x", "y").unwrap_err();
        assert!(error.contains("does not belong"), "{error}");
        child.kill().unwrap();
        child.wait().unwrap();
        let (id, _) = split_token(&token).unwrap();
        let forged = format!("{id}:{}", "0".repeat(64));
        assert!(procedures.fail_step(&forged, own, "x", "y").is_err());
        assert!(procedures.fail_step("garbage", own, "x", "y").is_err());
        assert_eq!(procedures.snapshot().iter().find(|s| s.id == id).unwrap().step, 4);
    }

    #[test]
    fn a_warned_step_is_numbered_checked_updated_and_leaves_failure_alone() {
        let procedures = Procedures::default();
        let own = std::process::id();
        let (_, token) = procedures.begin(own, "Update ns1", Some(4)).unwrap();
        procedures
            .next_step(&token, own, "sign closure for ns1", false, false)
            .unwrap();
        let warned = procedures
            .warn_step(&token, own, "activate ns1", "switch exited 4\x07; nothing regressed")
            .unwrap();
        assert_eq!((warned.step, warned.label.as_str()), (2, "activate ns1"));
        assert_eq!(warned.warning.as_deref(), Some("switch exited 4 ; nothing regressed"));
        assert_eq!(warned.failure, None);
        assert!(warned.validate().is_ok());
        // The same step again updates the warning in place.
        let again = procedures
            .warn_step(&token, own, "activate ns1", "a.service was failed before")
            .unwrap();
        assert_eq!(again.step, 2);
        assert_eq!(again.warning.as_deref(), Some("a.service was failed before"));
        let long = procedures
            .warn_step(&token, own, "activate ns1", &"x".repeat(3 * MAX_REASON_BYTES))
            .unwrap();
        assert_eq!(long.warning.unwrap().len(), MAX_REASON_BYTES);
        // A failure of that step keeps its warning, and a warning after it
        // keeps the failure.
        let failed = procedures.fail_step(&token, own, "activate ns1", "rolled back").unwrap();
        assert_eq!(failed.step, 2);
        assert_eq!(failed.failure.as_deref(), Some("rolled back"));
        assert!(failed.warning.is_some());
        let warned = procedures.warn_step(&token, own, "activate ns1", "still warned").unwrap();
        assert_eq!(warned.failure.as_deref(), Some("rolled back"));
        assert_eq!(warned.warning.as_deref(), Some("still warned"));
        // A warning of another step is a new step, without the old reports.
        let other = procedures.warn_step(&token, own, "activate ns2", "w").unwrap();
        assert_eq!((other.step, other.failure, other.warning.as_deref()), (3, None, Some("w")));
        // A later normal step clears it.
        let next = procedures
            .next_step(&token, own, "deploy secrets to ns1", true, false)
            .unwrap();
        assert_eq!((next.step, next.warning, next.failure), (4, None, None));
        // A failure reported as a new step starts without the warning.
        procedures.warn_step(&token, own, "activate ns3", "w").unwrap();
        let failed = procedures.fail_step(&token, own, "activate ns4", "f").unwrap();
        assert_eq!((failed.step, failed.warning), (6, None));
        assert!(procedures.warn_step(&token, own, " \x07 ", "x").is_err(), "empty label");
        // The token and descendant checks hold as for any request.
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let (_, foreign) = procedures.begin(child.id(), "Other", None).unwrap();
        let error = procedures.warn_step(&foreign, own, "x", "y").unwrap_err();
        assert!(error.contains("does not belong"), "{error}");
        child.kill().unwrap();
        child.wait().unwrap();
        let (id, _) = split_token(&token).unwrap();
        let forged = format!("{id}:{}", "0".repeat(64));
        assert!(procedures.warn_step(&forged, own, "x", "y").is_err());
        assert!(procedures.warn_step("garbage", own, "x", "y").is_err());
        assert_eq!(procedures.snapshot().iter().find(|s| s.id == id).unwrap().step, 6);
    }

    #[test]
    fn titles_and_declared_steps_are_validated() {
        let procedures = Procedures::default();
        assert!(procedures.begin(1, " \x1b ", None).is_err());
        assert!(procedures.begin(1, "x", Some(0)).is_err());
        assert!(procedures.begin(1, "x", Some(MAX_DECLARED_STEPS + 1)).is_err());
        for _ in 0..MAX_PROCEDURES {
            procedures.begin(1, "x", None).unwrap();
        }
        assert!(procedures.begin(1, "x", None).is_err());
    }

    #[test]
    fn progress_shows_on_the_current_step_until_the_next_step_or_report() {
        let procedures = Procedures::default();
        let own = std::process::id();
        let (_, token) = procedures.begin(own, "Update ns1", Some(3)).unwrap();
        procedures
            .next_step(&token, own, "SSH login to update@ns1", false, true)
            .unwrap();
        let step = procedures
            .progress_step(&token, own, "uploading the closure: 45%\x1b", Some(45))
            .unwrap();
        // It never numbers a step.
        assert_eq!((step.step, step.label.as_str()), (1, "SSH login to update@ns1"));
        assert_eq!(
            step.progress,
            Some(StepProgress { text: "uploading the closure: 45%".into(), percent: Some(45) })
        );
        assert_eq!(procedures.snapshot()[0].progress, step.progress);
        // A reconnect to the same destination keeps it; a new step clears it.
        let step = procedures
            .next_step(&token, own, "SSH login to update@ns1", false, true)
            .unwrap();
        assert!(step.progress.is_some());
        procedures.progress_step(&token, own, "activating the new system", None).unwrap();
        let step = procedures.fail_step(&token, own, "update of ns1", "rolled back").unwrap();
        assert_eq!((step.step, step.progress), (2, None));
        let step = procedures.progress_step(&token, own, "rolling back", None).unwrap();
        assert_eq!(step.failure.as_deref(), Some("rolled back"), "progress keeps the failure");
        let step = procedures.fail_step(&token, own, "update of ns1", "rolled back; restored").unwrap();
        assert_eq!((step.step, step.progress), (2, None), "the final report clears it");
        procedures.progress_step(&token, own, "deploying", None).unwrap();
        let step = procedures.next_step(&token, own, "deploy secrets to ns1", true, false).unwrap();
        assert_eq!((step.step, step.progress), (3, None));
        // Same checks as any report.
        assert!(procedures.progress_step(&token, own, " ", None).is_err());
        assert!(procedures.progress_step(&token, own, "x", Some(101)).is_err());
        let (id, _) = split_token(&token).unwrap();
        assert!(procedures.progress_step(&format!("{id}:{}", "0".repeat(64)), own, "x", None).is_err());
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let (_, foreign) = procedures.begin(child.id(), "Other", None).unwrap();
        let error = procedures.progress_step(&foreign, own, "x", None).unwrap_err();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(error.contains("does not belong"), "{error}");
    }
}
