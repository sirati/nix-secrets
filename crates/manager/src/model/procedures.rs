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

/// What a step asked the operator for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepKind {
    Values,
    SshLogin,
    Artifacts,
    Closure,
    Deployment,
}

impl StepKind {
    fn of(prompt: &SecretPrompt) -> Self {
        if prompt.closure_signature {
            Self::Closure
        } else if prompt.artifact_signature {
            Self::Artifacts
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
            Self::Artifacts => "artifacts signed",
            Self::Closure => "closure signed",
            Self::Deployment => "secrets deployed",
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
}

/// A step whose outcome arrived, as its dialog lists it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishedStep {
    pub step: ProcedureStep,
    pub kind: StepKind,
    /// What it did, or why it failed.
    pub text: String,
    pub succeeded: bool,
}

impl FinishedStep {
    /// `✓ step 1/3: closure signed` or `✗ step 2/3: SSH authentication to
    /// update@ns1: the operator denied SSH authentication`.
    pub fn line(&self) -> String {
        if self.succeeded {
            format!("✓ {}: {}", self.step.position(), self.text)
        } else {
            format!("✗ {}: {}: {}", self.step.position(), self.step.label, self.text)
        }
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
            Between::Result { succeeded: true, .. } => "done".into(),
            Between::Result { .. } if self.ended_early() && self.exit_code == Some(0) => {
                "ended early".into()
            }
            Between::Result { .. } => "failed".into(),
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
            finished.succeeded
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
    /// successful result does not hold the screen; like a notice it gives
    /// way.
    pub fn foreground_busy(&self) -> bool {
        !matches!(self.mode, Mode::Browse)
            || self.shown_prompt().is_some()
            || self.between_shown().is_some_and(|procedure| {
                !matches!(procedure.between, Some(Between::Result { succeeded: true, .. }))
            })
    }

    /// Whether the procedure waits for the operator: a prompt, a deployment
    /// approval on screen or parked, or a failure to acknowledge.
    pub fn procedure_waiting(&self, procedure: &Procedure) -> bool {
        !procedure.prompts.is_empty()
            || procedure.failed()
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
    }

    /// The backend reported the end of a procedure and, if known, how its
    /// command exited. Its dialog shows the result.
    pub fn procedure_ended(&mut self, id: &str, exit_code: Option<i32>) {
        let shown = self.between_shown().is_some_and(|procedure| procedure.id == id);
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
                        let all_done = procedure.finished.iter().all(|step| step.succeeded);
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
                        Between::Result {
                            succeeded: exit_code == Some(0) && all_done && !early,
                            text: summary,
                        }
                    }
                };
                let failed = matches!(result, Between::Result { succeeded: false, .. });
                let nothing_asked = procedure.finished.is_empty() && procedure.in_flight.is_empty();
                procedure.between = Some(result);
                if nothing_asked && !failed {
                    // A procedure that never asked anything leaves quietly.
                    procedure.between = None;
                } else if failed && !shown {
                    // A failure is never lost: it waits in the task bar.
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
        let Some(index) = self.procedures.iter().position(|procedure| {
            procedure.in_flight.iter().any(|flight| flight.request == request)
        }) else {
            return false;
        };
        let procedure = &mut self.procedures[index];
        let position = procedure
            .in_flight
            .iter()
            .position(|flight| flight.request == request)
            .expect("found above");
        let flight = procedure.in_flight.remove(position);
        let succeeded = outcome.is_ok();
        let text = match outcome {
            Ok(text) => text.unwrap_or_else(|| flight.kind.done().into()),
            Err(error) => error,
        };
        procedure.finished.push(FinishedStep {
            step: flight.step,
            kind: flight.kind,
            text,
            succeeded,
        });
        let open = !procedure.prompts.is_empty()
            || matches!(&self.mode, Mode::Approval(open) if approval_procedure(open) == procedure.id);
        let procedure = &mut self.procedures[index];
        if procedure.ended {
            // Its result is shown already; a late outcome joins its list.
            if let (false, Some(Between::Result { succeeded, .. })) =
                (succeeded, procedure.between.as_mut())
            {
                *succeeded = false;
            }
        } else if !open && procedure.in_flight.is_empty() && !procedure.failed() {
            procedure.between = Some(if !succeeded {
                Between::Result {
                    succeeded: false,
                    text: "The step failed.".into(),
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
        }
        self.tidy_procedures();
        true
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

    /// Removes a prompt the backend withdrew or that finished elsewhere.
    pub fn remove_prompt(&mut self, prompt_id: &str) -> bool {
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
        self.tidy_procedures();
        removed
    }

    /// Takes the prompt on screen, which the operator just answered.
    pub fn take_shown_prompt(&mut self) -> Option<SecretPrompt> {
        let id = self.foreground.clone()?;
        let prompt = self
            .procedure_mut(&id)
            .filter(|procedure| !procedure.minimised)?
            .prompts
            .pop_front()?;
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
            self.remove_prompt(id);
        }
        !expired.is_empty()
    }

    /// Stops the countdown of the prompt on screen; returns its id for the
    /// channel, or `None` if it had none.
    pub fn cancel_countdown(&mut self) -> Option<String> {
        let id = self.foreground.clone()?;
        let prompt = self
            .procedure_mut(&id)
            .filter(|procedure| !procedure.minimised)?
            .prompts
            .front_mut()?;
        prompt.deadline.take().map(|_| prompt.id.clone())
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
            // A success shown is a success seen.
            if matches!(procedure.between, Some(Between::Result { succeeded: true, .. })) {
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
