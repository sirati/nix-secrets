//! Procedures in the TUI: every prompt belongs to one. A prompt from a
//! requester inside `nix-secrets procedure` belongs to that procedure; any
//! other prompt or deployment approval is a procedure of its own.
//!
//! At most one procedure is in the foreground. Its dialog shows its first
//! waiting prompt, or its deployment approval. The others sit in the task
//! bar. A procedure never takes the foreground from another dialog: one
//! that starts while something else is open starts minimised, and its task
//! bar entry flashes until the operator restores it.
use super::*;
use crate::operator_channel::SecretPrompt;
use nix_secrets_core::procedure::ProcedureStep;
use std::time::{Duration, Instant};

/// How long one flash phase of a task bar entry lasts.
pub const FLASH_PERIOD: Duration = Duration::from_millis(500);

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
        }
    }

    /// `Update ns1 · step 2/4: sign closure for ns1`, or the title alone.
    pub fn heading(&self) -> String {
        match self.step.as_ref().filter(|step| step.step > 0) {
            Some(step) => format!("{} · {}: {}", self.title, step.position(), step.label),
            None => self.title.clone(),
        }
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

    /// Whether a dialog is on screen, so a new procedure must not open.
    pub fn foreground_busy(&self) -> bool {
        !matches!(self.mode, Mode::Browse) || self.shown_prompt().is_some()
    }

    /// Whether the procedure waits for the operator: a prompt, or a
    /// deployment approval on screen or parked.
    pub fn procedure_waiting(&self, procedure: &Procedure) -> bool {
        !procedure.prompts.is_empty()
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

    pub fn procedure_ended(&mut self, id: &str) {
        if let Some(procedure) = self.procedure_mut(id) {
            procedure.ended = true;
        }
        self.tidy_procedures();
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
        if self.shown_prompt().is_none() && !own_approval {
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
        }
        self.foreground = None;
        self.secret_scroll = 0;
        self.secret_details = false;
        self.modal_scroll = 0;
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
    /// answered, ended ones once their last prompt is answered.
    pub fn tidy_procedures(&mut self) {
        let finished = self
            .procedures
            .iter()
            .filter(|procedure| {
                (procedure.implicit || procedure.ended) && !self.procedure_waiting(procedure)
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
        }
        self.secret_scroll = 0;
        self.secret_details = false;
        self.tidy_procedures();
    }

    /// After (re)attaching: procedures of the backend that are not live
    /// any more ended meanwhile.
    pub fn procedures_synced(&mut self, live: &[String]) {
        for procedure in &mut self.procedures {
            if !procedure.implicit && !live.contains(&procedure.id) {
                procedure.ended = true;
            }
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
