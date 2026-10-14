//! Procedures in the TUI: every prompt belongs to one. A prompt from a
//! requester inside `nix-secrets procedure` belongs to that procedure; any
//! other prompt or deployment approval is a procedure of its own.
//!
//! At most one procedure is in the foreground. Its dialog shows its first
//! waiting prompt, or its deployment approval. The others sit in the task
//! bar. A procedure never takes the foreground from another dialog: one
//! that starts while something else is open starts minimised, and its task
//! bar entry flashes until the operator restores it.
//!
//! Between the steps of a `nix-secrets procedure` its dialog stays open
//! ([`Between`]): it lists the finished steps and shows a spinner until the
//! next prompt arrives in the same dialog. Once the last declared step is
//! done or the procedure ends, it shows the result there. A request of its
//! own still reports its outcome as a notice.
use super::*;
use crate::operator_channel::SecretPrompt;
use nix_secrets_core::procedure::ProcedureStep;
use std::time::{Duration, Instant};

/// How long one flash phase of a task bar entry lasts.
pub const FLASH_PERIOD: Duration = Duration::from_millis(500);
/// How often the spinner of a waiting procedure dialog moves.
pub const SPINNER_PERIOD: Duration = Duration::from_millis(120);
/// A denial this close to a step's deadline is its countdown running out.
const DEADLINE_SLACK: Duration = Duration::from_secs(2);

/// What a step asked the operator for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepKind {
    Values,
    SshLogin,
    SshLoginApproval,
    Artifacts,
    Closure,
    Deployment,
    /// A step the procedure's command reported as failed or warned about;
    /// nothing was asked.
    Reported,
}

impl StepKind {
    fn of(prompt: &SecretPrompt) -> Self {
        if prompt.closure_signature {
            Self::Closure
        } else if prompt.artifact_signature {
            Self::Artifacts
        } else if prompt.ssh_login {
            Self::SshLoginApproval
        } else if prompt.ssh_signature {
            Self::SshLogin
        } else {
            Self::Values
        }
    }

    /// What a successful step of this kind did.
    fn done(self) -> &'static str {
        match self {
            Self::Values => "secret values sent",
            Self::SshLogin => "SSH login signed",
            Self::SshLoginApproval => "SSH logins approved",
            Self::Artifacts => "artifacts signed",
            Self::Closure => "closure signed",
            Self::Deployment => "secrets deployed",
            Self::Reported => "reported",
        }
    }
}

/// A step that was asked and whose outcome has not arrived yet.
#[derive(Clone, Debug, Eq, PartialEq)]
struct InFlight {
    /// The prompt id, or the deployment request id.
    request: String,
    step: ProcedureStep,
    kind: StepKind,
    /// The operator denied it.
    denied: bool,
    /// When its countdown denies it, while it counts down.
    deadline: Option<Instant>,
}

/// How a finished step ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepOutcome {
    Done,
    Failed,
    Denied,
    /// Its countdown ran out before the operator answered.
    TimedOut,
    /// The procedure's command reported that it worked with a caveat.
    Warning,
}

impl StepOutcome {
    /// `timed out`, as in "timed out at step 1/3".
    pub fn verb(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::TimedOut => "timed out",
            Self::Warning => "warned",
        }
    }
}

/// A step whose outcome arrived, as its dialog lists it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishedStep {
    /// The prompt id, or the deployment request id.
    request: String,
    pub step: ProcedureStep,
    pub kind: StepKind,
    /// What it did, or why it failed.
    pub text: String,
    pub outcome: StepOutcome,
}

impl FinishedStep {
    /// Done, or done with a warning.
    pub fn succeeded(&self) -> bool {
        matches!(self.outcome, StepOutcome::Done | StepOutcome::Warning)
    }

    /// A step the procedure's command reported failed.
    fn reported_failed(&self) -> bool {
        self.kind == StepKind::Reported && self.outcome == StepOutcome::Failed
    }

    /// `✓ step 1/3: closure signed`, `⚠ step 2/3: activate ns1: nothing
    /// regressed` or `✗ step 2/3: SSH authentication to update@ns1: the
    /// operator denied SSH authentication`.
    pub fn line(&self) -> String {
        if self.outcome == StepOutcome::Warning {
            format!("⚠ {}: {}: {}", self.step.position(), self.step.label, self.text)
        } else if self.succeeded() {
            format!("✓ {}: {}", self.step.position(), self.text)
        } else {
            format!("✗ {}: {}: {}", self.step.position(), self.step.label, self.text)
        }
    }

    /// `timed out at step 1/3: sign closure for ns1`, for a step that did
    /// not succeed.
    pub fn missed(&self) -> Option<String> {
        (!self.succeeded()).then(|| {
            format!(
                "{} at {}: {}",
                self.outcome.verb(),
                self.step.position(),
                self.step.label
            )
        })
    }
}

/// What the dialog of a procedure shows while none of its prompts or
/// deployments is open.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Between {
    /// The operator answered; the TUI does the step (signing, deploying).
    Working { since: Instant },
    /// The step is done; the procedure's command works until it asks again.
    Waiting { since: Instant },
    /// The procedure is over, or its last declared step is done. A failure
    /// stays until the operator acknowledges it, a success until any key.
    Result { succeeded: bool, text: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Procedure {
    /// The backend's procedure id, or one made from the single request of
    /// an implicit procedure.
    pub id: String,
    pub title: String,
    /// The latest step the backend reported.
    pub step: Option<ProcedureStep>,
    /// Secret-channel prompts waiting for the operator, in arrival order.
    /// The dialog shows the first.
    pub prompts: VecDeque<SecretPrompt>,
    /// In the task bar, not on screen.
    pub minimised: bool,
    /// Started or advanced while minimised and not looked at since.
    pub flashing: bool,
    /// A procedure of one request, gone once that request is answered.
    pub implicit: bool,
    /// The backend reported its end; it goes once nothing waits in it.
    pub ended: bool,
    /// Its latest step is a deployment the TUI has not received yet; the
    /// TUI handles one claimed deployment at a time.
    pub awaiting_deployment: bool,
    /// Steps asked whose outcome has not arrived.
    in_flight: Vec<InFlight>,
    /// Steps whose outcome arrived, oldest first.
    pub finished: Vec<FinishedStep>,
    /// What its dialog shows between prompts; `None` while a prompt or
    /// deployment of it is open, or before its first step.
    pub between: Option<Between>,
    /// How its command exited, once it ended and if it said so.
    pub exit_code: Option<i32>,
    /// The result of a step its command reported failed while another step
    /// was open; it shows once nothing is.
    reported_failure: Option<String>,
}

impl Procedure {
    fn new(id: String, title: String, implicit: bool) -> Self {
        Self {
            id,
            title,
            step: None,
            prompts: VecDeque::new(),
            minimised: false,
            flashing: false,
            implicit,
            ended: false,
            awaiting_deployment: false,
            in_flight: Vec::new(),
            finished: Vec::new(),
            between: None,
            exit_code: None,
            reported_failure: None,
        }
    }

    /// `Update ns1 · step 2/4: sign closure for ns1`, or the title alone.
    pub fn heading(&self) -> String {
        match self.step.as_ref().filter(|step| step.step > 0) {
            Some(step) => format!("{} · {}: {}", self.title, step.position(), step.label),
            None => self.title.clone(),
        }
    }

    /// Whether its result failed and waits for an acknowledgement.
    pub fn failed(&self) -> bool {
        matches!(self.between, Some(Between::Result { succeeded: false, .. }))
    }

    /// The steps its command reported warnings for, oldest first.
    pub fn warnings(&self) -> impl Iterator<Item = &FinishedStep> {
        self.finished
            .iter()
            .filter(|step| step.outcome == StepOutcome::Warning)
    }

    /// Whether its result succeeded with warnings; like a failure it waits
    /// until the operator closes it.
    pub fn succeeded_with_warnings(&self) -> bool {
        matches!(self.between, Some(Between::Result { succeeded: true, .. }))
            && self.warnings().next().is_some()
    }

    /// Whether its result waits for the operator to close it with Enter.
    pub fn needs_acknowledgement(&self) -> bool {
        self.failed() || self.succeeded_with_warnings()
    }

    /// For a failed result, the step it missed: `timed out at step 1/3:
    /// sign closure for ns1`, `denied at …` or `failed at …`.
    pub fn missed(&self) -> Option<String> {
        self.missed_step().and_then(FinishedStep::missed)
    }

    /// For a failed result, the last step that did not succeed.
    pub fn missed_step(&self) -> Option<&FinishedStep> {
        if !self.failed() {
            return None;
        }
        self.finished.iter().rev().find(|step| !step.succeeded())
    }

    /// The step after the last finished one: `step 3/3`, or `step 3`.
    fn next_position(&self) -> String {
        let mut next = self
            .finished
            .last()
            .map(|finished| finished.step.clone())
            .or_else(|| self.step.clone())
            .unwrap_or_else(|| ProcedureStep {
                id: self.id.clone(),
                title: self.title.clone(),
                step: 0,
                steps: None,
                label: String::new(),
                deployment: false,
                failure: None,
                warning: None,
            });
        next.step += 1;
        next.position()
    }

    /// The title of the dialog between prompts.
    pub fn between_title(&self) -> Option<String> {
        let state = match self.between.as_ref()? {
            Between::Working { .. } => match &self.step {
                Some(step) if step.step > 0 => format!("{} in progress", step.position()),
                _ => "working".into(),
            },
            Between::Waiting { .. } => format!("waiting for {}", self.next_position()),
            Between::Result { succeeded: true, .. } if self.succeeded_with_warnings() => {
                "succeeded with warnings".into()
            }
            Between::Result { succeeded: true, .. } => "done".into(),
            Between::Result { .. } if self.ended_early() && self.exit_code == Some(0) => {
                "ended early".into()
            }
            Between::Result { .. } => self.missed().unwrap_or_else(|| "failed".into()),
        };
        Some(format!("{} · {state}", self.title))
    }

    /// The finished steps, then what happens now. `spinner` is the current
    /// spinner frame.
    pub fn between_body(&self, spinner: char, now: Instant) -> Option<String> {
        let between = self.between.as_ref()?;
        let mut lines = self.finished.iter().map(FinishedStep::line).collect::<Vec<_>>();
        let seconds = |since: &Instant| now.saturating_duration_since(*since).as_secs();
        match between {
            Between::Working { since } => {
                let what = self
                    .step
                    .as_ref()
                    .filter(|step| step.step > 0)
                    .map_or_else(|| "working".into(), |step| {
                        format!("{}: {}", step.position(), step.label)
                    });
                lines.push(format!("{spinner} {what} … {} s", seconds(since)));
            }
            Between::Waiting { since } => {
                // An SSH login may reconnect, which asks for the same step again.
                let or_login = if self
                    .finished
                    .last()
                    .is_some_and(|finished| finished.kind == StepKind::SshLogin)
                {
                    " or another SSH login"
                } else {
                    ""
                };
                lines.push(format!(
                    "{spinner} waiting for {}{or_login} … {} s",
                    self.next_position(),
                    seconds(since)
                ));
            }
            Between::Result { text, .. } => {
                if !lines.is_empty() {
                    lines.push(String::new());
                }
                lines.push(text.clone());
            }
        }
        Some(lines.join("\n"))
    }

    /// The last step it asked.
    fn reached(&self) -> u32 {
        self.step.as_ref().map_or(0, |step| step.step)
    }

    /// Ended with fewer steps than it declared.
    fn ended_early(&self) -> bool {
        self.ended
            && self
                .step
                .as_ref()
                .and_then(|step| step.steps)
                .is_some_and(|steps| self.reached() < steps)
    }

    /// Whether its last declared step is done.
    fn last_step_done(&self) -> bool {
        self.finished.last().is_some_and(|finished| {
            finished.succeeded()
                && finished
                    .step
                    .steps
                    .is_some_and(|steps| finished.step.step >= steps)
        })
    }
}

/// The procedure of a prompt.
pub fn prompt_procedure(prompt: &SecretPrompt) -> String {
    prompt
        .procedure
        .as_ref()
        .map(|step| step.id.clone())
        .unwrap_or_else(|| format!("request:{}", prompt.id))
}

/// The procedure of a deployment approval.
pub fn approval_procedure(request: &ApprovalRequest) -> String {
    request
        .procedure
        .as_ref()
        .map(|step| step.id.clone())
        .unwrap_or_else(|| format!("deployment:{}", request.id))
}

/// `Failed at step 2/4: activate ns1: rolled back`, for a step the
/// procedure's command reported failed.
fn reported_failure(step: &FinishedStep) -> String {
    format!("Failed at {}: {}: {}", step.step.position(), step.step.label, step.text)
}

/// How a procedure's command ended, for its result.
fn exit_text(exit_code: Option<i32>) -> String {
    match exit_code {
        Some(0) => "The command finished successfully.".into(),
        Some(code) => format!("The command failed with exit status {code}."),
        None => "The command ended without reporting its exit status.".into(),
    }
}

impl Model {
    pub fn procedure(&self, id: &str) -> Option<&Procedure> {
        self.procedures.iter().find(|procedure| procedure.id == id)
    }

    fn procedure_mut(&mut self, id: &str) -> Option<&mut Procedure> {
        self.procedures.iter_mut().find(|procedure| procedure.id == id)
    }

    /// The prompt on screen: the first of the foreground procedure.
    pub fn shown_prompt(&self) -> Option<&SecretPrompt> {
        let id = self.foreground.as_deref()?;
        self.procedure(id)
            .filter(|procedure| !procedure.minimised)?
            .prompts
            .front()
    }

    /// The procedure whose dialog shows what happens between its prompts:
    /// the foreground one, with no prompt or other dialog open.
    pub fn between_shown(&self) -> Option<&Procedure> {
        if !matches!(self.mode, Mode::Browse) {
            return None;
        }
        let id = self.foreground.as_deref()?;
        self.procedure(id).filter(|procedure| {
            !procedure.minimised && procedure.prompts.is_empty() && procedure.between.is_some()
        })
    }

    /// Whether a dialog is on screen, so a new procedure must not open. A
    /// successful result without warnings does not hold the screen; like a
    /// notice it gives way.
    pub fn foreground_busy(&self) -> bool {
        !matches!(self.mode, Mode::Browse)
            || self.shown_prompt().is_some()
            || self.between_shown().is_some_and(|procedure| {
                !matches!(procedure.between, Some(Between::Result { succeeded: true, .. }))
                    || procedure.succeeded_with_warnings()
            })
    }

    /// Whether the procedure waits for the operator: a prompt, a deployment
    /// approval on screen or parked, or a failure or warnings to acknowledge.
    pub fn procedure_waiting(&self, procedure: &Procedure) -> bool {
        !procedure.prompts.is_empty()
            || procedure.needs_acknowledgement()
            || self
                .pending_approvals
                .iter()
                .any(|request| approval_procedure(request) == procedure.id)
            || matches!(&self.mode, Mode::Approval(request)
                if approval_procedure(request) == procedure.id)
    }

    pub(super) fn ensure_procedure(
        &mut self,
        id: &str,
        title: impl FnOnce() -> String,
        step: Option<&ProcedureStep>,
    ) -> &mut Procedure {
        let index = match self.procedures.iter().position(|procedure| procedure.id == id) {
            Some(index) => index,
            None => {
                let implicit = step.is_none();
                let title = step.map_or_else(title, |step| step.title.clone());
                self.procedures
                    .push(Procedure::new(id.to_owned(), title, implicit));
                self.procedures.len() - 1
            }
        };
        let procedure = &mut self.procedures[index];
        if let Some(step) = step {
            // Steps only move forward; a late copy of an older one is kept
            // out.
            if procedure
                .step
                .as_ref()
                .is_none_or(|known| step.step >= known.step)
            {
                procedure.title = step.title.clone();
                procedure.step = Some(step.clone());
            }
        }
        procedure
    }

    /// Puts a procedure that now waits for the operator on screen when
    /// nothing else is, else leaves it in the task bar, flashing.
    pub(super) fn arrive(&mut self, id: &str) {
        let in_foreground = self.foreground.as_deref() == Some(id)
            && self.procedure(id).is_some_and(|procedure| !procedure.minimised);
        if in_foreground {
            // Its own dialog is open, or it was in the foreground between
            // steps and nothing else was opened since.
            let own_dialog = self.shown_prompt().is_some()
                || matches!(&self.mode, Mode::Approval(request) if approval_procedure(request) == id);
            if own_dialog || matches!(self.mode, Mode::Browse) {
                return;
            }
        } else if !self.foreground_busy() {
            self.foreground = Some(id.to_owned());
            let procedure = self.procedure_mut(id).expect("procedure exists");
            procedure.minimised = false;
            procedure.flashing = false;
            self.secret_scroll = 0;
            self.secret_details = false;
            // The procedure that gave way has nothing more to show.
            self.tidy_procedures();
            return;
        }
        if self.foreground.as_deref() == Some(id) {
            self.foreground = None;
        }
        let procedure = self.procedure_mut(id).expect("procedure exists");
        procedure.minimised = true;
        procedure.flashing = true;
    }

    /// A prompt from the operator channel.
    pub fn offer_prompt(&mut self, prompt: SecretPrompt) {
        let id = prompt_procedure(&prompt);
        let title = super::super::ui::secret_request::title(&prompt);
        let step = prompt.procedure.clone();
        let procedure = self.ensure_procedure(&id, || title, step.as_ref());
        let was_waiting = !procedure.prompts.is_empty();
        if let (false, Some(step)) = (procedure.implicit, step) {
            procedure.in_flight.push(InFlight {
                request: prompt.id.clone(),
                step,
                kind: StepKind::of(&prompt),
                denied: false,
                deadline: prompt.deadline,
            });
            procedure.between = None;
        }
        procedure.prompts.push_back(prompt);
        if !was_waiting {
            self.arrive(&id);
        }
    }

    /// A procedure started or reached a new step.
    pub fn procedure_step(&mut self, step: ProcedureStep) {
        let id = step.id.clone();
        let procedure = self.ensure_procedure(&id, String::new, Some(&step));
        if step.deployment {
            procedure.awaiting_deployment = true;
        }
        if let Some(warning) = step.warning.clone() {
            self.step_reported(step.clone(), StepOutcome::Warning, warning);
        }
        if let Some(failure) = step.failure.clone() {
            self.step_reported(step, StepOutcome::Failed, failure);
        }
    }

    /// The procedure's command reported a step as failed, or as done with
    /// a warning. It is listed with its reason; a failure fails the
    /// procedure like a failed prompt, a warning keeps its successful result
    /// until the operator closes it. A later report of the same kind about
    /// the same step only updates the reason.
    fn step_reported(&mut self, step: ProcedureStep, outcome: StepOutcome, reason: String) {
        let Some(index) = self.procedures.iter().position(|procedure| procedure.id == step.id)
        else {
            return;
        };
        let kind = if outcome == StepOutcome::Warning { "warning" } else { "failed" };
        let request = format!("{kind}:{}:{}", step.id, step.step);
        let procedure = &mut self.procedures[index];
        if let Some(known) = procedure
            .finished
            .iter_mut()
            .find(|finished| finished.request == request)
        {
            let old = reported_failure(known);
            known.text = reason;
            known.step = step;
            let new = reported_failure(known);
            if outcome == StepOutcome::Warning {
                return;
            }
            let shown = match &mut procedure.between {
                Some(Between::Result { text, .. }) => Some(text),
                _ => None,
            };
            for text in shown.into_iter().chain(procedure.reported_failure.as_mut()) {
                if let Some(rest) = text.strip_prefix(&old) {
                    *text = format!("{new}{rest}");
                }
            }
            return;
        }
        let flight = InFlight {
            request,
            step,
            kind: StepKind::Reported,
            denied: false,
            deadline: None,
        };
        self.record_step(index, flight, outcome, reason);
        self.tidy_procedures();
    }

    /// The backend reported the end of a procedure and, if known, how its
    /// command exited. Its dialog shows the result.
    pub fn procedure_ended(&mut self, id: &str, exit_code: Option<i32>) {
        // Its dialog on screen shows the result in place.
        let shown = matches!(self.mode, Mode::Browse)
            && self.foreground.as_deref() == Some(id)
            && self.procedure(id).is_some_and(|procedure| !procedure.minimised);
        if let Some(procedure) = self.procedure_mut(id) {
            procedure.ended = true;
            procedure.exit_code = exit_code;
            // Implicit procedures report as notices; one still asking shows
            // its prompt first.
            if !procedure.implicit && procedure.prompts.is_empty() {
                let exit = exit_text(exit_code);
                let result = match procedure.between.take() {
                    Some(Between::Result { succeeded, text }) => Between::Result {
                        succeeded: succeeded && exit_code == Some(0),
                        text: format!("{text}\n{exit}"),
                    },
                    _ if procedure.finished.is_empty() && procedure.in_flight.is_empty() => {
                        // Nothing was asked: only a known failure is worth
                        // reporting.
                        Between::Result {
                            succeeded: !matches!(exit_code, Some(code) if code != 0),
                            text: exit,
                        }
                    }
                    _ => {
                        // The exit status speaks for steps whose outcome has not
                        // arrived yet: `deploy --wait` exits only once deployed.
                        let all_done = procedure.finished.iter().all(FinishedStep::succeeded);
                        let early = procedure.ended_early();
                        let summary = if early {
                            let reached = procedure.reached();
                            let declared = procedure
                                .step
                                .as_ref()
                                .and_then(|step| step.steps)
                                .unwrap_or(reached);
                            format!("Ended after step {reached} of {declared}. {exit}")
                        } else {
                            exit
                        };
                        // A step the command reported failed says why first.
                        let summary = match procedure
                            .finished
                            .iter()
                            .rev()
                            .find(|step| step.reported_failed())
                        {
                            Some(reported) => format!("{}\n{summary}", reported_failure(reported)),
                            None => summary,
                        };
                        Between::Result {
                            succeeded: exit_code == Some(0) && all_done && !early,
                            text: summary,
                        }
                    }
                };
                let failed = matches!(result, Between::Result { succeeded: false, .. });
                let warned = !failed && procedure.warnings().next().is_some();
                let nothing_asked = procedure.finished.is_empty() && procedure.in_flight.is_empty();
                procedure.between = Some(result);
                if nothing_asked && !failed {
                    // A procedure that never asked anything leaves quietly.
                    procedure.between = None;
                } else if (failed || warned) && !shown {
                    // A failure or a warning is never lost: it waits in the
                    // task bar.
                    procedure.minimised = true;
                    procedure.flashing = true;
                }
            }
        }
        if self.foreground.as_deref() == Some(id)
            && self.procedure(id).is_some_and(|procedure| procedure.minimised)
        {
            self.foreground = None;
        }
        self.tidy_procedures();
    }

    /// The operator answered the prompt of a procedure step; its dialog
    /// shows the step working until the outcome arrives.
    fn step_answered(&mut self, id: &str) {
        if let Some(procedure) = self.procedure_mut(id) {
            if !procedure.implicit && procedure.prompts.is_empty() {
                procedure.between = Some(Between::Working {
                    since: Instant::now(),
                });
            }
        }
    }

    /// The operator answered a deployment dialog of a procedure; its dialog
    /// shows the deployment working until the next stage or the outcome.
    pub fn deployment_answered(&mut self, request: &ApprovalRequest) {
        // The TUI deploys one request at a time: an older deployment step
        // still waiting for its outcome will not get one.
        for procedure in &mut self.procedures {
            procedure.in_flight.retain(|flight| {
                flight.kind != StepKind::Deployment || flight.request == request.id
            });
        }
        let Some(step) = request.procedure.clone() else {
            return;
        };
        let Some(procedure) = self.procedure_mut(&step.id) else {
            return;
        };
        if procedure.implicit {
            return;
        }
        if !procedure.in_flight.iter().any(|flight| flight.request == request.id) {
            procedure.in_flight.push(InFlight {
                request: request.id.clone(),
                step,
                kind: StepKind::Deployment,
                denied: false,
                deadline: None,
            });
        }
        if procedure.prompts.is_empty() {
            procedure.between = Some(Between::Working {
                since: Instant::now(),
            });
        }
    }

    /// The deployment of a procedure that is being deployed, if any. The TUI
    /// handles one claimed deployment at a time.
    pub fn deployment_in_flight(&self) -> Option<String> {
        self.procedures.iter().find_map(|procedure| {
            procedure
                .in_flight
                .iter()
                .find(|flight| flight.kind == StepKind::Deployment)
                .map(|flight| flight.request.clone())
        })
    }

    /// The outcome of a step: `Ok` with what it did, if more than its kind
    /// says, or `Err` with why it failed. Returns whether `request` was a
    /// step of a procedure; if not, the caller reports it as a notice.
    pub fn step_finished(&mut self, request: &str, outcome: Result<Option<String>, String>) -> bool {
        let Some((index, flight)) = self.take_in_flight(request) else {
            // A step closed here already, when its countdown ran out or its
            // requester left, lists why; the channel's denial that follows
            // adds nothing.
            return self
                .procedures
                .iter()
                .any(|procedure| procedure.finished.iter().any(|step| step.request == request));
        };
        let (outcome, text) = match outcome {
            Ok(text) => (
                StepOutcome::Done,
                text.unwrap_or_else(|| flight.kind.done().into()),
            ),
            Err(error) if flight.denied => (StepOutcome::Denied, error),
            // The channel denies at the same deadline as the countdown here.
            Err(error)
                if flight
                    .deadline
                    .is_some_and(|deadline| Instant::now() + DEADLINE_SLACK >= deadline) =>
            {
                (StepOutcome::TimedOut, error)
            }
            Err(error) => (StepOutcome::Failed, error),
        };
        self.record_step(index, flight, outcome, text);
        self.tidy_procedures();
        true
    }

    /// Removes the step asked by `request` from what is in flight.
    fn take_in_flight(&mut self, request: &str) -> Option<(usize, InFlight)> {
        self.procedures.iter_mut().enumerate().find_map(|(index, procedure)| {
            let position = procedure
                .in_flight
                .iter()
                .position(|flight| flight.request == request)?;
            Some((index, procedure.in_flight.remove(position)))
        })
    }

    /// Lists a finished step in its procedure's dialog and, once nothing of
    /// the procedure is open or in flight, shows what comes next. A step
    /// that did not succeed fails the procedure; unless its dialog is on
    /// screen, its task bar entry flashes.
    fn record_step(&mut self, index: usize, flight: InFlight, outcome: StepOutcome, text: String) {
        let succeeded = matches!(outcome, StepOutcome::Done | StepOutcome::Warning);
        let procedure = &mut self.procedures[index];
        procedure.finished.push(FinishedStep {
            request: flight.request,
            step: flight.step,
            kind: flight.kind,
            text,
            outcome,
        });
        let reported = (flight.kind == StepKind::Reported && outcome == StepOutcome::Failed)
            .then(|| procedure.finished.last().map(reported_failure))
            .flatten();
        let open = !procedure.prompts.is_empty()
            || matches!(&self.mode, Mode::Approval(open) if approval_procedure(open) == procedure.id);
        let procedure = &mut self.procedures[index];
        if procedure.ended {
            match procedure.between.as_mut() {
                // Its result is shown already; a late outcome joins its list.
                Some(Between::Result { succeeded: shown, .. }) => *shown &= succeeded,
                // It ended while this step was open: its result shows now.
                _ if !open => {
                    let (id, exit_code) = (procedure.id.clone(), procedure.exit_code);
                    self.procedure_ended(&id, exit_code);
                }
                _ => {}
            }
        } else if !open && procedure.in_flight.is_empty() && !procedure.failed() {
            // A failure the command reported while a step was open shows
            // once nothing is.
            let reported = reported.or_else(|| procedure.reported_failure.take());
            procedure.reported_failure = None;
            let succeeded = succeeded && reported.is_none();
            procedure.between = Some(if !succeeded {
                Between::Result {
                    succeeded: false,
                    text: reported.unwrap_or_else(|| match outcome {
                        StepOutcome::Denied => "You denied the step.".into(),
                        StepOutcome::TimedOut => "Nobody answered the step in time.".into(),
                        _ => "The step failed.".into(),
                    }),
                }
            } else if procedure.last_step_done() {
                Between::Result {
                    succeeded: true,
                    text: "All steps are done.".into(),
                }
            } else {
                Between::Waiting {
                    since: Instant::now(),
                }
            });
            if !succeeded {
                let shown = self.foreground.as_deref() == Some(self.procedures[index].id.as_str())
                    && !self.procedures[index].minimised;
                if !shown {
                    self.procedures[index].minimised = true;
                    self.procedures[index].flashing = true;
                }
            }
        } else if let (Some(text), false) = (reported, procedure.failed()) {
            // Listed now; the result waits until the open step is done.
            procedure.reported_failure = Some(text);
            if procedure.minimised {
                procedure.flashing = true;
            }
        }
    }

    /// Closes the result in the procedure dialog on screen.
    pub fn dismiss_result(&mut self) {
        let Some(id) = self.between_shown().map(|procedure| procedure.id.clone()) else {
            return;
        };
        if let Some(procedure) = self.procedure_mut(&id) {
            if matches!(procedure.between, Some(Between::Result { .. })) {
                procedure.between = None;
            }
        }
        self.tidy_procedures();
    }

    /// Whether a spinner is on screen and due to move. Moves it.
    pub fn spinner_tick(&mut self, now: Instant) -> bool {
        let spinning = self.between_shown().is_some_and(|procedure| {
            matches!(
                procedure.between,
                Some(Between::Working { .. } | Between::Waiting { .. })
            )
        });
        if !spinning || now < self.spinner_due {
            return false;
        }
        self.spinner_due = now + SPINNER_PERIOD;
        true
    }

    /// Removes a prompt that finished elsewhere or whose answer failed.
    pub fn remove_prompt(&mut self, prompt_id: &str) -> bool {
        let removed = self.drop_prompt(prompt_id);
        self.tidy_procedures();
        removed
    }

    fn drop_prompt(&mut self, prompt_id: &str) -> bool {
        let shown = self.shown_prompt().is_some_and(|prompt| prompt.id == prompt_id);
        let mut removed = false;
        for procedure in &mut self.procedures {
            let before = procedure.prompts.len();
            procedure.prompts.retain(|prompt| prompt.id != prompt_id);
            removed |= procedure.prompts.len() != before;
        }
        if shown {
            self.secret_scroll = 0;
            self.secret_details = false;
        }
        removed
    }

    /// Closes a prompt nobody answered. A step of a procedure is listed as
    /// missed in its dialog right away, so it never looks busy; the
    /// channel's denial that follows is absorbed by [`Self::step_finished`].
    fn prompt_missed(&mut self, prompt_id: &str, outcome: StepOutcome, text: String) -> bool {
        let removed = self.drop_prompt(prompt_id);
        if let Some((index, flight)) = self.take_in_flight(prompt_id) {
            self.record_step(index, flight, outcome, text);
        }
        self.tidy_procedures();
        removed
    }

    /// The backend withdrew a prompt: its requester left, or it gave up.
    pub fn withdraw_prompt(&mut self, prompt_id: &str) -> bool {
        self.prompt_missed(
            prompt_id,
            StepOutcome::Failed,
            "withdrawn: its requester left".into(),
        )
    }

    /// Takes the prompt on screen, which the operator just answered.
    pub fn take_shown_prompt(&mut self, approved: bool) -> Option<SecretPrompt> {
        let id = self.foreground.clone()?;
        let procedure = self
            .procedure_mut(&id)
            .filter(|procedure| !procedure.minimised)?;
        let prompt = procedure.prompts.pop_front()?;
        if let Some(flight) = procedure
            .in_flight
            .iter_mut()
            .find(|flight| flight.request == prompt.id)
        {
            flight.denied = !approved;
        }
        self.secret_scroll = 0;
        self.secret_details = false;
        self.step_answered(&id);
        self.tidy_procedures();
        Some(prompt)
    }

    /// Drops prompts whose countdown ran out; the channel denies them at the
    /// same moment. Returns whether any went.
    pub fn expire_prompts(&mut self, now: Instant) -> bool {
        let expired = self
            .procedures
            .iter()
            .flat_map(|procedure| &procedure.prompts)
            .filter(|prompt| prompt.deadline.is_some_and(|deadline| now >= deadline))
            .map(|prompt| prompt.id.clone())
            .collect::<Vec<_>>();
        for id in &expired {
            self.prompt_missed(
                id,
                StepOutcome::TimedOut,
                format!(
                    "no answer within {} s",
                    crate::operator_channel::DECISION_TIMEOUT.as_secs()
                ),
            );
        }
        !expired.is_empty()
    }

    /// Stops the countdown of the prompt on screen; returns its id for the
    /// channel, or `None` if it had none.
    pub fn cancel_countdown(&mut self) -> Option<String> {
        let id = self.foreground.clone()?;
        let procedure = self
            .procedure_mut(&id)
            .filter(|procedure| !procedure.minimised)?;
        let prompt = procedure.prompts.front_mut()?;
        let request = prompt.deadline.take().map(|_| prompt.id.clone())?;
        for flight in &mut procedure.in_flight {
            if flight.request == request {
                flight.deadline = None;
            }
        }
        Some(request)
    }

    /// `m`: moves the foreground procedure's dialog to the task bar.
    pub fn minimise(&mut self) -> bool {
        if self.foreground.is_none() {
            // A deployment dialog opened directly belongs to its own procedure.
            if let Mode::Approval(request) = &self.mode {
                let id = approval_procedure(request);
                let title = format!("Deploy {}", request.target);
                let step = request.procedure.clone();
                self.ensure_procedure(&id, || title, step.as_ref());
                self.foreground = Some(id);
            }
        }
        let Some(id) = self.foreground.clone() else {
            return false;
        };
        let own_approval =
            matches!(&self.mode, Mode::Approval(request) if approval_procedure(request) == id);
        if self.shown_prompt().is_none() && !own_approval && self.between_shown().is_none() {
            return false;
        }
        if own_approval {
            let Mode::Approval(request) = std::mem::replace(&mut self.mode, Mode::Browse) else {
                unreachable!()
            };
            // An unfinished host-change review must be read again from the
            // top once restored; a finished one stays read.
            if self
                .host_review
                .as_ref()
                .is_some_and(|(token, seen)| !seen && request.host_mutation_token.as_ref() == Some(token))
            {
                self.host_review = None;
            }
            self.pending_approvals.push_front(request);
        }
        if let Some(procedure) = self.procedure_mut(&id) {
            procedure.minimised = true;
            procedure.flashing = false;
            // A success shown is a success seen; warnings wait to be closed.
            if matches!(procedure.between, Some(Between::Result { succeeded: true, .. }))
                && !procedure.succeeded_with_warnings()
            {
                procedure.between = None;
            }
        }
        self.foreground = None;
        self.secret_scroll = 0;
        self.secret_details = false;
        self.modal_scroll = 0;
        self.tidy_procedures();
        true
    }

    /// Brings a procedure from the task bar to the foreground. Another
    /// procedure dialog on screen is minimised; any other dialog must be
    /// closed first.
    pub fn restore(&mut self, id: &str) -> Result<(), &'static str> {
        if self.procedure(id).is_none() {
            return Err("that procedure has finished");
        }
        let procedure_dialog = self.shown_prompt().is_some()
            || self.between_shown().is_some()
            || matches!(self.mode, Mode::Approval(_));
        if !matches!(self.mode, Mode::Browse | Mode::Approval(_)) && !procedure_dialog {
            return Err("close the open dialog before restoring a procedure");
        }
        if self.foreground.as_deref() != Some(id) {
            self.minimise();
            if matches!(self.mode, Mode::Approval(_)) {
                // An approval whose procedure lost track of it still holds
                // the screen; it cannot be parked safely.
                return Err("answer the open deployment request first");
            }
            if self.procedure(id).is_none() {
                return Err("that procedure has finished");
            }
        }
        self.foreground = Some(id.to_owned());
        if let Some(procedure) = self.procedure_mut(id) {
            procedure.minimised = false;
            procedure.flashing = false;
        }
        self.secret_scroll = 0;
        self.secret_details = false;
        self.modal_scroll = 0;
        if self.shown_prompt().is_none() {
            self.show_pending_approval();
        }
        Ok(())
    }

    /// `M`: restores the next procedure that waits, flashing ones first,
    /// after the one in the foreground.
    pub fn restore_next(&mut self) -> Result<(), &'static str> {
        let current = self
            .foreground
            .as_deref()
            .and_then(|id| self.procedures.iter().position(|procedure| procedure.id == id));
        let count = self.procedures.len();
        let order = (1..=count).map(|offset| (current.unwrap_or(count - 1) + offset) % count.max(1));
        let candidates = order
            .filter(|index| Some(*index) != current)
            .filter(|index| self.procedure_waiting(&self.procedures[*index]))
            .collect::<Vec<_>>();
        let next = candidates
            .iter()
            .find(|index| self.procedures[**index].flashing)
            .or(candidates.first())
            .copied()
            .ok_or("no other procedure waits for you")?;
        let id = self.procedures[next].id.clone();
        self.restore(&id)
    }

    /// Removes procedures with nothing left to show: implicit ones once
    /// answered, ended ones once their last prompt is answered and their
    /// result was seen. A successful result stays only while on screen; a
    /// failure until acknowledged.
    pub fn tidy_procedures(&mut self) {
        let foreground = self.foreground.clone();
        let finished = self
            .procedures
            .iter()
            .filter(|procedure| {
                let result_on_screen = foreground.as_deref() == Some(procedure.id.as_str())
                    && !procedure.minimised
                    && matches!(procedure.between, Some(Between::Result { .. }));
                (procedure.implicit || procedure.ended)
                    && !self.procedure_waiting(procedure)
                    && !result_on_screen
            })
            .map(|procedure| procedure.id.clone())
            .collect::<Vec<_>>();
        self.procedures
            .retain(|procedure| !finished.contains(&procedure.id));
        if self
            .foreground
            .as_deref()
            .is_some_and(|id| self.procedure(id).is_none())
        {
            self.foreground = None;
        }
    }

    /// The operator channel broke: no prompt on it can be answered any more.
    /// They are dropped, never answered; the backend keeps the requests
    /// waiting and sends them again once the channel is attached again.
    pub fn connection_lost(&mut self) {
        for procedure in &mut self.procedures {
            procedure.prompts.clear();
            procedure
                .in_flight
                .retain(|flight| flight.kind == StepKind::Deployment);
        }
        self.secret_scroll = 0;
        self.secret_details = false;
        self.tidy_procedures();
    }

    /// After (re)attaching: procedures of the backend that are not live
    /// any more ended meanwhile.
    pub fn procedures_synced(&mut self, live: &[String]) {
        let gone = self
            .procedures
            .iter()
            .filter(|procedure| !procedure.implicit && !procedure.ended && !live.contains(&procedure.id))
            .map(|procedure| procedure.id.clone())
            .collect::<Vec<_>>();
        for id in gone {
            self.procedure_ended(&id, None);
        }
        self.tidy_procedures();
    }

    /// Alternates the flash phase every [`FLASH_PERIOD`]. Returns whether
    /// a flashing entry needs a redraw.
    pub fn flash_tick(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.flash_since) < FLASH_PERIOD {
            return false;
        }
        self.flash_since = now;
        self.flash_on = !self.flash_on;
        self.procedures.iter().any(|procedure| procedure.flashing)
    }
}
