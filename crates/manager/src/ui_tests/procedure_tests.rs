//! Procedures in the TUI: one dialog with a common title for all prompts
//! of a procedure, minimising to the task bar, several at once, no focus
//! stealing, and a countdown only on the first step that the operator can
//! cancel.
use super::*;
use crate::model::HostMutationReview;
use crate::operator_channel::SecretPrompt;
use crate::secret_values::RequestedValue;
use crate::ui::ProcedureEvent;
use nix_secrets_core::procedure::ProcedureStep;
use nix_secrets_core::secret_request::ProcessInfo;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Channel {
    prompts: Vec<SecretPrompt>,
    events: Vec<ProcedureEvent>,
    answers: Vec<(String, bool)>,
    cancelled: Vec<String>,
    host_decisions: Vec<(bool, String)>,
}

impl SecretWriter for Channel {
    fn write(
        &mut self,
        _path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        Err(("unused".into(), value))
    }
    fn poll_secret_prompt(&mut self) -> Option<SecretPrompt> {
        (!self.prompts.is_empty()).then(|| self.prompts.remove(0))
    }
    fn poll_procedure_event(&mut self) -> Option<ProcedureEvent> {
        (!self.events.is_empty()).then(|| self.events.remove(0))
    }
    fn answer_secret(&mut self, id: &str, approved: bool, _count: usize) -> Result<(), String> {
        self.answers.push((id.into(), approved));
        Ok(())
    }
    fn cancel_countdown(&mut self, id: &str) -> Result<(), String> {
        self.cancelled.push(id.into());
        Ok(())
    }
    fn approve_host_mutations(
        &mut self,
        accepted: bool,
        token: &str,
    ) -> Result<Option<ApprovalRequest>, String> {
        self.host_decisions.push((accepted, token.into()));
        Ok(None)
    }
}

fn step(id: &str, title: &str, number: u32, label: &str) -> ProcedureStep {
    ProcedureStep {
        id: id.into(),
        title: title.into(),
        step: number,
        steps: Some(3),
        label: label.into(),
        deployment: false,
    }
}

/// A prompt as the operator channel builds it: the first step of a
/// procedure, or a request of its own, counts down.
fn prompt(id: &str, procedure: Option<ProcedureStep>) -> SecretPrompt {
    let countdown = procedure.as_ref().is_none_or(ProcedureStep::countdown);
    SecretPrompt {
        id: id.into(),
        values: vec![RequestedValue {
            identifier: "root@ns1".into(),
            kind: "SSH authentication".into(),
            description: None,
            recipients: vec![],
        }],
        identity: "SSH agent on this client".into(),
        requester: ProcessInfo {
            pid: 42,
            executable: Some("/bin/nix-secrets".into()),
            argv: vec!["nix-secrets".into(), "with-ssh-agent".into()],
            cwd: None,
        },
        parent: None,
        reason: None,
        ssh_signature: true,
        artifact_signature: false,
        closure_signature: false,
        deadline: countdown.then(|| Instant::now() + Duration::from_secs(120)),
        procedure,
    }
}

fn tick(model: &mut Model, channel: &mut Channel) {
    crate::ui::secret_request_tick_for_tests(model, channel);
}

fn render(model: &Model) -> String {
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 45)).unwrap();
    crate::ui::render_for_tests(&mut terminal, model)
}

const UPDATE: &str = "proc-1-aaaa";
const INSTALL: &str = "proc-2-bbbb";

#[test]
fn prompts_of_one_procedure_share_one_dialog_with_its_title_and_step() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel
        .events
        .push(ProcedureEvent::Step(step(UPDATE, "Update ns1", 0, "starting")));
    tick(&mut model, &mut channel);
    assert_eq!(model.procedures.len(), 1);
    assert!(model.shown_prompt().is_none(), "nothing asked yet");
    assert!(render(&model).contains("Update ns1 · working"));
    channel.prompts.push(prompt(
        "ssh",
        Some(step(UPDATE, "Update ns1", 1, "SSH authentication to root@ns1")),
    ));
    let mut closure = prompt(
        "closure",
        Some(step(UPDATE, "Update ns1", 2, "sign closure for ns1")),
    );
    closure.ssh_signature = false;
    closure.closure_signature = true;
    channel.prompts.push(closure);
    tick(&mut model, &mut channel);
    // Both wait in the same procedure; the dialog shows the first.
    assert_eq!(model.procedures.len(), 1);
    assert_eq!(model.procedures[0].prompts.len(), 2);
    let screen = render(&model);
    assert!(
        screen.contains("Update ns1 · step 1/3: SSH authentication to root@ns1"),
        "{screen}"
    );
    assert!(screen.contains("SSH authentication request from nix-secrets (pid 42)"));
    model.acknowledge();
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    assert_eq!(channel.answers, [("ssh".to_owned(), true)]);
    // The next step opens in the same dialog, under the same title.
    let screen = render(&model);
    assert!(
        screen.contains("Update ns1 · step 2/3: sign closure for ns1"),
        "{screen}"
    );
    assert!(screen.contains("Closure signing request from nix-secrets (pid 42)"));
    reduce(&mut model, UiEvent::Character('n'), &mut channel);
    // The deployment step joins the same procedure.
    let deployment = ApprovalRequest {
        id: "deploy-1".into(),
        target: "ns1".into(),
        create: vec!["ns1.services.a.b".into()],
        procedure: Some(step(UPDATE, "Update ns1", 3, "deploy secrets to ns1")),
        ..Default::default()
    };
    reduce(&mut model, UiEvent::Approval(deployment), &mut channel);
    assert!(matches!(model.mode, Mode::Approval(_)));
    let screen = render(&model);
    assert!(
        screen.contains("Update ns1 · step 3/3 › Deploy ns1 · step 2/3: choose what to deploy"),
        "{screen}"
    );
    assert_eq!(model.procedures.len(), 1, "still one procedure");
    // A failed end shows in its dialog until acknowledged; then it leaves.
    reduce(&mut model, UiEvent::Character('n'), &mut channel);
    model.finish_approval("deploy-1");
    channel.events.push(ProcedureEvent::Ended(UPDATE.into(), Some(1)));
    tick(&mut model, &mut channel);
    let screen = render(&model);
    assert!(screen.contains("Update ns1 · failed"), "{screen}");
    assert!(screen.contains("The command failed with exit status 1."), "{screen}");
    reduce(&mut model, UiEvent::Character('x'), &mut channel);
    assert_eq!(model.procedures.len(), 1, "only Enter or OK closes a failure");
    reduce(&mut model, UiEvent::Enter, &mut channel);
    assert!(model.procedures.is_empty());
}

#[test]
fn m_minimises_to_the_task_bar_and_restoring_brings_it_back() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(prompt(
        "ssh",
        Some(step(UPDATE, "Update ns1", 1, "SSH authentication to root@ns1")),
    ));
    tick(&mut model, &mut channel);
    assert!(model.shown_prompt().is_some());
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    assert!(model.shown_prompt().is_none(), "minimised");
    assert!(channel.answers.is_empty(), "minimising never answers");
    assert!(model.procedures[0].minimised);
    let screen = render(&model);
    assert!(screen.contains("Procedures"), "{screen}");
    assert!(
        screen.contains("Update ns1 · step 1/3: SSH authentication to root@ns1 · waiting for you"),
        "{screen}"
    );
    // The tree has the keys again.
    reduce(&mut model, UiEvent::Character('f'), &mut channel);
    assert!(model.shown_prompt().is_none());
    // A click on the entry restores it.
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Procedure(0)),
        &mut channel,
    );
    assert!(model.shown_prompt().is_some());
    // So does M, and a deployment dialog minimises the same way.
    reduce(&mut model, UiEvent::Character('n'), &mut channel);
    let deployment = ApprovalRequest {
        id: "deploy-1".into(),
        target: "ns1".into(),
        create: vec!["ns1.services.a.b".into()],
        procedure: Some(step(UPDATE, "Update ns1", 2, "deploy secrets to ns1")),
        ..Default::default()
    };
    reduce(&mut model, UiEvent::Approval(deployment), &mut channel);
    assert!(matches!(model.mode, Mode::Approval(_)));
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    assert!(matches!(model.mode, Mode::Browse));
    assert_eq!(model.pending_approvals.len(), 1, "parked, not answered");
    reduce(&mut model, UiEvent::Character('M'), &mut channel);
    assert!(
        matches!(&model.mode, Mode::Approval(request) if request.id == "deploy-1"),
        "M restores the deployment dialog"
    );
}

#[test]
fn a_new_procedure_starts_minimised_and_flashes_without_taking_the_screen() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(prompt(
        "ssh",
        Some(step(UPDATE, "Update ns1", 1, "SSH authentication to root@ns1")),
    ));
    tick(&mut model, &mut channel);
    channel.prompts.push(prompt(
        "install",
        Some(step(INSTALL, "Install ns2", 1, "sign artifacts for ns2")),
    ));
    tick(&mut model, &mut channel);
    // Two procedures each have a prompt waiting at once; the first keeps
    // the screen and the keys.
    assert_eq!(model.procedures.len(), 2);
    assert_eq!(model.shown_prompt().unwrap().id, "ssh");
    let install = model.procedure(INSTALL).unwrap();
    assert!(install.minimised && install.flashing);
    // The entry alternates its style on the flash phase.
    let style_of = |model: &Model| {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 45)).unwrap();
        let screen = crate::ui::render_for_tests(&mut terminal, model);
        let row = screen
            .lines()
            .position(|line| line.contains("Install ns2 · step 1/3"))
            .expect("the flashing entry is listed");
        let column = screen.lines().nth(row).unwrap().find("Install").unwrap();
        let column = screen.lines().nth(row).unwrap()[..column].chars().count();
        terminal.backend().buffer()[(column as u16, row as u16)].style()
    };
    // The prompt dialog covers the task bar; minimise it to look.
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    let before = style_of(&model);
    model.flash_since = Instant::now() - Duration::from_secs(1);
    assert!(model.flash_tick(Instant::now()), "a flashing entry redraws");
    assert_ne!(before, style_of(&model), "the flash alternates the style");
    // Answering the first does not open the second on its own.
    reduce(&mut model, UiEvent::Character('M'), &mut channel);
    assert_eq!(model.shown_prompt().unwrap().id, "install", "M prefers the flashing one");
    assert!(!model.procedure(INSTALL).unwrap().flashing);
    reduce(&mut model, UiEvent::Character('M'), &mut channel);
    assert_eq!(model.shown_prompt().unwrap().id, "ssh", "M switches procedures");
    reduce(&mut model, UiEvent::Character('n'), &mut channel);
    assert!(model.shown_prompt().is_none());
    assert!(model.procedure(INSTALL).unwrap().minimised);
    // With nothing in the foreground, a new procedure opens directly.
    let mut quiet = super::model(true);
    channel.prompts.push(prompt("own", None));
    tick(&mut quiet, &mut channel);
    assert_eq!(quiet.shown_prompt().unwrap().id, "own");
    assert!(!quiet.procedures[0].flashing);
}

#[test]
fn a_deployment_of_another_procedure_waits_in_the_task_bar() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(prompt(
        "ssh",
        Some(step(UPDATE, "Update ns1", 1, "SSH authentication to root@ns1")),
    ));
    tick(&mut model, &mut channel);
    let deployment = ApprovalRequest {
        id: "deploy-2".into(),
        target: "ns2".into(),
        create: vec!["ns2.services.a.b".into()],
        procedure: Some(step(INSTALL, "Install ns2", 2, "deploy secrets to ns2")),
        ..Default::default()
    };
    reduce(&mut model, UiEvent::Approval(deployment), &mut channel);
    assert!(matches!(model.mode, Mode::Browse), "it did not open");
    assert_eq!(model.shown_prompt().unwrap().id, "ssh");
    assert!(model.procedure(INSTALL).unwrap().flashing);
    reduce(&mut model, UiEvent::Character('n'), &mut channel);
    assert!(matches!(model.mode, Mode::Browse), "answering does not open it");
    reduce(&mut model, UiEvent::Character('M'), &mut channel);
    assert!(matches!(&model.mode, Mode::Approval(request) if request.id == "deploy-2"));
}

#[test]
fn only_the_first_step_counts_down_and_c_cancels_it() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(prompt(
        "first",
        Some(step(UPDATE, "Update ns1", 1, "SSH authentication to root@ns1")),
    ));
    tick(&mut model, &mut channel);
    let screen = render(&model);
    assert!(screen.contains("denies in"), "{screen}");
    assert!(screen.contains("c Keep waiting"), "{screen}");
    reduce(&mut model, UiEvent::Character('c'), &mut channel);
    assert_eq!(channel.cancelled, ["first"]);
    assert!(channel.answers.is_empty(), "cancelling never answers");
    assert!(model.shown_prompt().unwrap().deadline.is_none());
    let screen = render(&model);
    assert!(!screen.contains("denies in"), "{screen}");
    assert!(!screen.contains("c Keep waiting"), "{screen}");
    // Once cancelled, nothing expires it.
    tick(&mut model, &mut channel);
    assert!(model.shown_prompt().is_some());
    reduce(&mut model, UiEvent::Character('c'), &mut channel);
    assert_eq!(channel.cancelled.len(), 1, "nothing left to cancel");
    // The button does the same.
    reduce(&mut model, UiEvent::Character('n'), &mut channel);
    // The procedure's dialog stays open for its outcome; minimise it.
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    channel.prompts.push(prompt("own", None));
    tick(&mut model, &mut channel);
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Shortcut(Shortcut::Character('c'))),
        &mut channel,
    );
    assert_eq!(channel.cancelled, ["first", "own"]);
    reduce(&mut model, UiEvent::Character('n'), &mut channel);
    // A later step has no countdown at all.
    channel.prompts.push(prompt(
        "second",
        Some(step(UPDATE, "Update ns1", 2, "sign closure for ns1")),
    ));
    tick(&mut model, &mut channel);
    assert!(model.shown_prompt().unwrap().deadline.is_none());
    let screen = render(&model);
    assert!(!screen.contains("denies in"), "{screen}");
    // An expired first step closes, minimised or not.
    let mut expired = prompt(
        "expired",
        Some(step(INSTALL, "Install ns2", 1, "sign artifacts for ns2")),
    );
    expired.deadline = Some(Instant::now());
    channel.prompts.push(expired);
    tick(&mut model, &mut channel);
    assert!(model.procedure(INSTALL).is_none() || model.procedure(INSTALL).unwrap().prompts.is_empty());
}

#[test]
fn a_withdrawn_request_leaves_its_procedure() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(prompt("gone", None));
    tick(&mut model, &mut channel);
    assert!(model.shown_prompt().is_some());
    channel.events.push(ProcedureEvent::Withdrawn("gone".into()));
    tick(&mut model, &mut channel);
    assert!(model.shown_prompt().is_none());
    assert!(model.procedures.is_empty());
    assert!(channel.answers.is_empty(), "the channel answers withdrawn requests itself");
}

#[test]
fn a_minimised_host_review_must_be_read_again_after_restoring() {
    let mut model = model(true);
    let mut channel = Channel::default();
    let review = ApprovalRequest {
        id: "same-deploy".into(),
        target: "producer".into(),
        host_mutation_token: Some("shown-batch".into()),
        host_mutations: vec![HostMutationReview {
            identifier: "receiver.services.report.known-hosts".into(),
            kind: "report receiver host identity".into(),
            previous: vec!["SHA256:old".into()],
            proposed: vec!["SHA256:new".into()],
        }],
        procedure: Some(step(UPDATE, "Update ns1", 2, "deploy secrets to producer")),
        ..Default::default()
    };
    reduce(&mut model, UiEvent::Approval(review), &mut channel);
    // Drawn three lines too tall; one line read.
    *model.host_review_rendered.borrow_mut() = Some("shown-batch".into());
    model.scroll_limit.set(3);
    reduce(&mut model, UiEvent::Down, &mut channel);
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    // Another dialog leaves its scroll offset behind.
    model.modal_scroll = 10;
    reduce(&mut model, UiEvent::Character('M'), &mut channel);
    assert!(matches!(model.mode, Mode::Approval(_)));
    *model.host_review_rendered.borrow_mut() = Some("shown-batch".into());
    model.scroll_limit.set(3);
    reduce(&mut model, UiEvent::Character('y'), &mut channel);
    assert!(channel.host_decisions.is_empty(), "the review restarts at its top");
    for _ in 0..3 {
        reduce(&mut model, UiEvent::Down, &mut channel);
    }
    reduce(&mut model, UiEvent::Character('y'), &mut channel);
    assert_eq!(channel.host_decisions, [(true, "shown-batch".to_owned())]);
}

#[test]
fn a_lost_connection_clears_requests_without_answering_and_shows_the_outage() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(prompt(
        "ssh",
        Some(step(UPDATE, "Update ns1", 1, "SSH authentication to root@ns1")),
    ));
    channel
        .events
        .push(ProcedureEvent::Step(step(INSTALL, "Install ns2", 0, "starting")));
    tick(&mut model, &mut channel);
    assert!(model.shown_prompt().is_some());
    // A minimised deployment of the same procedure is parked.
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    channel.events.push(ProcedureEvent::Disconnected);
    tick(&mut model, &mut channel);
    assert!(model.procedures.iter().all(|procedure| procedure.prompts.is_empty()));
    assert!(channel.answers.is_empty(), "nothing was answered");
    model.backend_problem = Some("connection refused".into());
    assert!(render(&model).contains("Disconnected from the backend, reconnecting: connection refused"));
    // Attached again: only live procedures stay.
    channel.events.push(ProcedureEvent::Reconnected);
    channel.events.push(ProcedureEvent::Synced(vec![UPDATE.into()]));
    tick(&mut model, &mut channel);
    assert!(model.procedure(UPDATE).is_some());
    assert!(model.procedure(INSTALL).is_none(), "ended while disconnected");
    assert!(model
        .notifications
        .iter()
        .chain(model.message.iter())
        .any(|notice| notice.text.contains("Reconnected")));
    // The request comes back and is shown from the start.
    channel.prompts.push(prompt(
        "ssh",
        Some(step(UPDATE, "Update ns1", 1, "SSH authentication to root@ns1")),
    ));
    tick(&mut model, &mut channel);
    assert_eq!(model.procedure(UPDATE).unwrap().prompts.len(), 1);
}

#[test]
fn a_deployment_lost_to_a_reconnection_leaves_no_parked_dialog() {
    let mut model = model(true);
    let mut channel = Channel::default();
    let deployment = ApprovalRequest {
        id: "deploy-1".into(),
        target: "ns1".into(),
        create: vec!["ns1.services.a.b".into()],
        procedure: Some(step(UPDATE, "Update ns1", 2, "deploy secrets to ns1")),
        ..Default::default()
    };
    reduce(&mut model, UiEvent::Approval(deployment), &mut channel);
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    assert_eq!(model.pending_approvals.len(), 1);
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::ApprovalLost(crate::async_ui::RECONNECTED_APPROVAL.into()),
    );
    assert!(model.pending_approvals.is_empty());
    reduce(&mut model, UiEvent::Character('M'), &mut channel);
    assert!(!matches!(model.mode, Mode::Approval(_)), "no stale dialog can be restored");
}

/// A closure-signing prompt of `UPDATE` at `number` of `steps`.
fn closure_step(id: &str, number: u32, steps: u32) -> SecretPrompt {
    let mut step = step(UPDATE, "Update ns1", number, "sign closure for ns1");
    step.steps = Some(steps);
    let mut prompt = prompt(id, Some(step));
    prompt.ssh_signature = false;
    prompt.closure_signature = true;
    prompt
}

fn signed(model: &mut Model, id: &str, result: Result<(), String>) {
    crate::ui::apply_completion_for_tests(
        model,
        crate::ui::Completion::ArtifactSignatureFinished {
            id: id.into(),
            requester: "nix-secrets (pid 42)".into(),
            result,
        },
    );
}

#[test]
fn a_finished_step_waits_in_the_procedure_dialog_for_the_next_prompt() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(closure_step("closure", 1, 3));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    assert_eq!(channel.answers, [("closure".to_owned(), true)]);
    // The dialog stays open while the TUI signs.
    let screen = render(&model);
    assert!(screen.contains("┌Update ns1 · step 1/3 in progress"), "{screen}");
    signed(&mut model, "closure", Ok(()));
    // Done: no notice, the same dialog reports it and waits.
    assert!(model.message.is_none(), "no notice between steps");
    assert!(model.notifications.is_empty());
    let screen = render(&model);
    assert!(!screen.contains("┌Notice"), "{screen}");
    assert!(screen.contains("┌Update ns1 · waiting for step 2/3"), "{screen}");
    assert!(screen.contains("✓ step 1/3: closure signed"), "{screen}");
    assert!(screen.contains("waiting for step 2/3 …"), "{screen}");
    assert!(screen.contains("m Minimise"), "{screen}");
    // The keys stay with the dialog.
    reduce(&mut model, UiEvent::Character('f'), &mut channel);
    assert_eq!(model.filter, crate::model::ViewFilter::Required);
    // Another procedure does not take the screen from it.
    channel.prompts.push(prompt(
        "other",
        Some(step(INSTALL, "Install ns2", 1, "sign artifacts for ns2")),
    ));
    tick(&mut model, &mut channel);
    assert!(model.procedure(INSTALL).unwrap().flashing);
    assert!(render(&model).contains("┌Update ns1 · waiting for step 2/3"));
    // m minimises it; a click on its entry brings it back, still waiting.
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    assert!(model.between_shown().is_none());
    reduce(&mut model, UiEvent::Click(MouseTarget::Procedure(0)), &mut channel);
    assert!(render(&model).contains("┌Update ns1 · waiting for step 2/3"));
    // The next step opens in the same dialog.
    let mut login = prompt(
        "login",
        Some(step(UPDATE, "Update ns1", 2, "SSH authentication to update@ns1")),
    );
    login.deadline = None;
    channel.prompts.push(login);
    tick(&mut model, &mut channel);
    let screen = render(&model);
    assert!(
        screen.contains("┌Update ns1 · step 2/3: SSH authentication to update@ns1"),
        "{screen}"
    );
    assert!(!screen.contains("waiting for step"), "{screen}");
    // After an SSH login another login to it may follow as the same step.
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::SshSignatureFinished {
            id: "login".into(),
            requester: "nix-secrets (pid 42)".into(),
            result: Ok(()),
        },
    );
    let screen = render(&model);
    assert!(screen.contains("✓ step 2/3: SSH login signed"), "{screen}");
    assert!(screen.contains("waiting for step 3/3 or another SSH login …"), "{screen}");
}

#[test]
fn the_spinner_moves_on_a_timer_only_while_its_dialog_is_on_screen() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(closure_step("closure", 1, 3));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    signed(&mut model, "closure", Ok(()));
    let now = Instant::now();
    model.spinner_due = now;
    assert!(model.spinner_tick(now), "due: redraw");
    assert!(!model.spinner_tick(now), "not again before the period");
    assert!(!model.spinner_tick(now + crate::model::SPINNER_PERIOD / 2));
    assert!(model.spinner_tick(now + crate::model::SPINNER_PERIOD));
    // Minimised, nothing spins and nothing redraws for it.
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    assert!(!model.spinner_tick(now + crate::model::SPINNER_PERIOD * 10));
}

#[test]
fn the_last_step_shows_the_result_in_the_procedure_dialog() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(closure_step("closure", 1, 2));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    signed(&mut model, "closure", Ok(()));
    // The deployment is the last step; it opens in the same dialog.
    let mut last = step(UPDATE, "Update ns1", 2, "deploy secrets to ns1");
    last.steps = Some(2);
    last.deployment = true;
    let deployment = ApprovalRequest {
        id: "deploy-1".into(),
        target: "ns1".into(),
        create: vec!["ns1.services.a.b".into()],
        procedure: Some(last),
        ..Default::default()
    };
    reduce(&mut model, UiEvent::Approval(deployment), &mut channel);
    assert!(matches!(model.mode, Mode::Approval(_)));
    assert!(!render(&model).contains("waiting for step"));
    reduce(&mut model, UiEvent::Character('y'), &mut channel);
    model.finish_approval("deploy-1");
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::Deployed {
            generated: vec![],
            skipped: vec![],
            summary: Some(crate::model::DeploySummary {
                target: "ns1".into(),
                sent: 4,
                generated: 0,
                left_out: vec![],
                missing: vec![],
            }),
        },
    );
    assert!(model.message.is_none(), "no notice for the deployment either");
    let screen = render(&model);
    assert!(screen.contains("┌Update ns1 · done"), "{screen}");
    assert!(screen.contains("✓ step 1/2: closure signed"), "{screen}");
    assert!(
        screen.contains("✓ step 2/2: secrets deployed to ns1: 4 sent · 0 generated"),
        "{screen}"
    );
    assert!(screen.contains("All steps are done."), "{screen}");
    // The command exits successfully: the result says so.
    channel.events.push(ProcedureEvent::Ended(UPDATE.into(), Some(0)));
    tick(&mut model, &mut channel);
    let screen = render(&model);
    assert!(screen.contains("The command finished successfully."), "{screen}");
    // Any key closes a success, and the procedure leaves.
    reduce(&mut model, UiEvent::Character('x'), &mut channel);
    assert!(model.procedures.is_empty());
    assert!(model.between_shown().is_none());
}

#[test]
fn a_success_gives_way_to_the_next_procedure() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(closure_step("closure", 1, 1));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    signed(&mut model, "closure", Ok(()));
    channel.events.push(ProcedureEvent::Ended(UPDATE.into(), Some(0)));
    tick(&mut model, &mut channel);
    assert!(render(&model).contains("┌Update ns1 · done"));
    channel.prompts.push(prompt(
        "next",
        Some(step(INSTALL, "Install ns2", 1, "sign artifacts for ns2")),
    ));
    tick(&mut model, &mut channel);
    assert_eq!(model.shown_prompt().unwrap().id, "next");
    assert!(model.procedure(UPDATE).is_none(), "its success was shown");
}

#[test]
fn a_requester_that_exits_mid_procedure_leaves_its_outcome_in_the_dialog() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(closure_step("closure", 1, 3));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    signed(&mut model, "closure", Ok(()));
    assert!(render(&model).contains("waiting for step 2/3"));
    channel.events.push(ProcedureEvent::Ended(UPDATE.into(), Some(2)));
    tick(&mut model, &mut channel);
    let screen = render(&model);
    assert!(screen.contains("┌Update ns1 · failed"), "{screen}");
    assert!(screen.contains("✓ step 1/3: closure signed"), "{screen}");
    assert!(
        screen.contains("Ended after step 1 of 3. The command failed with exit status 2."),
        "{screen}"
    );
    assert!(screen.contains("Enter OK"), "{screen}");
    assert!(!screen.contains("waiting for step"), "{screen}");
    // It is not lost when minimised: the entry waits for the operator.
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    assert!(render(&model).contains("Update ns1 · step 1/3: sign closure for ns1 · failed · waiting for you"));
    reduce(&mut model, UiEvent::Character('M'), &mut channel);
    assert!(render(&model).contains("┌Update ns1 · failed"));
    reduce(&mut model, UiEvent::Enter, &mut channel);
    assert!(model.procedures.is_empty());

    // Exiting successfully before the declared total still shows.
    channel.prompts.push(closure_step("again", 1, 3));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    signed(&mut model, "again", Ok(()));
    channel.events.push(ProcedureEvent::Ended(UPDATE.into(), Some(0)));
    tick(&mut model, &mut channel);
    let screen = render(&model);
    assert!(screen.contains("┌Update ns1 · ended early"), "{screen}");
    assert!(screen.contains("Ended after step 1 of 3."), "{screen}");
}

#[test]
fn a_failed_or_denied_step_shows_in_the_dialog_and_a_minimised_one_flashes() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(closure_step("closure", 1, 3));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::Character('n'), &mut channel);
    assert_eq!(channel.answers, [("closure".to_owned(), false)]);
    signed(
        &mut model,
        "closure",
        Err("the operator denied closure signing".into()),
    );
    assert!(model.message.is_none(), "{:?}", model.message);
    let screen = render(&model);
    assert!(screen.contains("┌Update ns1 · failed"), "{screen}");
    assert!(
        screen.contains("✗ step 1/3: sign closure for ns1: the operator denied closure signing"),
        "{screen}"
    );
    reduce(&mut model, UiEvent::Enter, &mut channel);
    assert!(model.between_shown().is_none());

    // A step of a minimised procedure that fails flashes in the task bar.
    channel.prompts.push(closure_step("second", 2, 3));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    reduce(&mut model, UiEvent::Character('m'), &mut channel);
    signed(&mut model, "second", Err("signing failed".into()));
    let procedure = model.procedure(UPDATE).unwrap();
    assert!(procedure.minimised && procedure.flashing && procedure.failed());
}

#[test]
fn a_request_of_its_own_still_reports_with_a_notice() {
    let mut model = model(true);
    let mut channel = Channel::default();
    channel.prompts.push(prompt("own", None));
    tick(&mut model, &mut channel);
    reduce(&mut model, UiEvent::ConfirmLoss, &mut channel);
    assert!(model.procedures.is_empty());
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::SshSignatureFinished {
            id: "own".into(),
            requester: "nix-secrets (pid 42)".into(),
            result: Ok(()),
        },
    );
    assert!(model.message_text().unwrap().contains("Returned one SSH authentication signature"));
}

#[test]
fn an_end_that_overtakes_the_deployment_outcome_still_shows_both() {
    let mut model = model(true);
    let mut channel = Channel::default();
    let mut last = step(UPDATE, "Update ns1", 1, "deploy secrets to ns1");
    last.steps = Some(1);
    let deployment = ApprovalRequest {
        id: "deploy-1".into(),
        target: "ns1".into(),
        create: vec!["ns1.services.a.b".into()],
        procedure: Some(last),
        ..Default::default()
    };
    reduce(&mut model, UiEvent::Approval(deployment), &mut channel);
    reduce(&mut model, UiEvent::Character('y'), &mut channel);
    model.finish_approval("deploy-1");
    // `deploy --wait` exited 0: the deployment succeeded.
    channel.events.push(ProcedureEvent::Ended(UPDATE.into(), Some(0)));
    tick(&mut model, &mut channel);
    assert!(render(&model).contains("┌Update ns1 · done"));
    crate::ui::apply_completion_for_tests(
        &mut model,
        crate::ui::Completion::Deployed {
            generated: vec![],
            skipped: vec![],
            summary: None,
        },
    );
    assert!(model.message.is_none());
    let screen = render(&model);
    assert!(screen.contains("┌Update ns1 · done"), "{screen}");
    assert!(screen.contains("✓ step 1/1: secrets deployed"), "{screen}");
}
