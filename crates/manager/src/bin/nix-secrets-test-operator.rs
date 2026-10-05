//! TEST-ONLY headless o//!     --secret-identity PATH --known-hosts PATH [--answer y|p|n] [--requests N]
//!     [--set IDENTIFIER=VALUE ...]
//! ```
//!
//! `--set` first stores a value through the TUI's own write path, which
//! encrypts it to the leaf's recipients.erator for VM tests, built only with the
//! `test-operator` feature and never installed by the nix-secrets packages.
//!
//! It is the TUI without a terminal: the same controller, AsyncWriter,
//! approval reducer and drive loop, fed by a scripted frontend that presses
//! the keys an operator would. Approval requests from `nix-secrets deploy`
//! therefore take the real path: host-key check, the create/replace/generate
//! dialog, the missing-values refusal, then SSH to the target's receiver.
//!
//! ```text
//! nix-secrets-test-operator --backend-socket PATH --schema-file PATH
//!     --secret-identity PATH --known-hosts PATH [--answer y|p|n] [--requests N]
//!     [--launcher PATH]
//! ```
//!
//! `--host-value-answer y|n` independently accepts or rejects host-provided
//! nonempty replacements; it defaults to `n`.
//!
//! `--answer` is the key pressed on each deployment dialog: `y` approves,
//! `p` then `y` approves a partial deployment, and `n` rejects. It also
//! trusts an unknown host key with `y`. It exits after `--requests`
//! deployment requests finished (default 1) and prints each notice on
//! stdout.
use nix_secrets_core::Schema;
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::async_ui::AsyncWriter;
use nix_secrets_manager::client::BackendClient;
use nix_secrets_manager::controller::Controller;
use nix_secrets_manager::model::{Mode, Model, NoticeSeverity};
use nix_secrets_manager::socket::connect_verified;
use nix_secrets_manager::ui::{drive, Frontend, UiEvent};
use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

struct RemoteOptions {
    destination: String,
    repository: PathBuf,
    socket: PathBuf,
    control: PathBuf,
}

struct Options {
    remote: Option<RemoteOptions>,
    socket: PathBuf,
    schema: PathBuf,
    identity: PathBuf,
    known_hosts: PathBuf,
    answer: char,
    host_value_answer: char,
    requests: usize,
    set: Vec<(String, String)>,
    /// Decrypts through this nix-secrets-1password launcher, as the TUI
    /// does with 1Password, so a test can count its authorizations.
    launcher: Option<PathBuf>,
}

fn parse() -> Result<Options, String> {
    let mut arguments = std::env::args().skip(1);
    let (mut socket, mut schema, mut identity, mut known_hosts) = (None, None, None, None);
    let mut answer = 'y';
    let mut host_value_answer = 'n';
    let mut requests = 1;
    let mut set = Vec::new();
    let mut launcher = None;
    let (mut remote_backend, mut remote_repository, mut remote_socket, mut control_socket) = (None,None,None,None);
    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or(format!("{argument} requires a value"))
        };
        match argument.as_str() {
            "--remote-backend" => remote_backend = Some(value()?),
            "--remote-repository" => remote_repository = Some(PathBuf::from(value()?)),
            "--remote-backend-socket" => remote_socket = Some(PathBuf::from(value()?)),
            "--control-socket" => control_socket = Some(PathBuf::from(value()?)),
            "--backend-socket" => socket = Some(PathBuf::from(value()?)),
            "--schema-file" => schema = Some(PathBuf::from(value()?)),
            "--secret-identity" => identity = Some(PathBuf::from(value()?)),
            "--known-hosts" => known_hosts = Some(PathBuf::from(value()?)),
            "--answer" => {
                answer = match value()?.as_str() {
                    "y" => 'y',
                    "p" => 'p',
                    "n" => 'n',
                    other => return Err(format!("--answer must be y, p or n, not {other}")),
                }
            }
            "--host-value-answer" => {
                host_value_answer = match value()?.as_str() {
                    "y" => 'y',
                    "n" => 'n',
                    _ => return Err("--host-value-answer must be y or n".into()),
                };
            }
            "--set" => {
                let assignment = value()?;
                let (identifier, text) = assignment
                    .split_once('=')
                    .ok_or("--set needs IDENTIFIER=VALUE")?;
                set.push((identifier.to_owned(), text.replace("\\n", "\n")));
            }
            "--set-file" => {
                let assignment = value()?;
                let (identifier, path) = assignment
                    .split_once('=')
                    .ok_or("--set-file needs IDENTIFIER=PATH")?;
                let text = std::fs::read_to_string(path)
                    .map_err(|error| format!("cannot read {path}: {error}"))?;
                set.push((identifier.to_owned(), text));
            }
            "--launcher" => launcher = Some(PathBuf::from(value()?)),
            "--requests" => requests = value()?.parse().map_err(|_| "--requests needs a number")?,
            other => return Err(format!("unexpected argument {other}")),
        }
    }
    let remote = if remote_backend.is_some() || remote_repository.is_some() || remote_socket.is_some() || control_socket.is_some() {
        Some(RemoteOptions {
            destination: remote_backend.ok_or("--remote-backend is required for remote mode")?,
            repository: remote_repository.ok_or("--remote-repository is required for remote mode")?,
            socket: remote_socket.ok_or("--remote-backend-socket is required for remote mode")?,
            control: control_socket.ok_or("--control-socket is required for remote mode")?,
        })
    } else { None };
    Ok(Options {
        remote,
        socket: socket.ok_or("--backend-socket is required")?,
        schema: schema.ok_or("--schema-file is required")?,
        identity: identity.ok_or("--secret-identity is required")?,
        known_hosts: known_hosts.ok_or("--known-hosts is required")?,
        answer,
        host_value_answer,
        requests,
        set,
        launcher,
    })
}

/// Presses the operator's keys from what the model shows.
struct Scripted {
    answer: char,
    host_value_answer: char,
    remaining: usize,
    queued: VecDeque<UiEvent>,
    /// The deployment request whose dialog was already answered.
    answered: Option<(String, u8, Option<String>)>,
    /// The answered dialog failed and is still open.
    failed: bool,
    busy: bool,
}

impl Frontend for Scripted {
    fn draw(&mut self, model: &Model) -> io::Result<()> {
        if let Some(notice) = &model.message {
            // Its acknowledgement is still queued.
            if !self.queued.is_empty() {
                return Ok(());
            }
            let failure = notice.severity == NoticeSeverity::Failure;
            println!(
                "{}: {}",
                if failure { "failure" } else { "notice" },
                notice.text.replace('\n', " | ")
            );
            if failure && matches!(model.mode, Mode::Approval(_)) {
                // The dialog stays open after a refusal; reject it next so
                // the requester learns why.
                self.failed = true;
            } else if self.answered.take().is_some() || failure {
                // A finished deployment, a rejection, or a request refused
                // before its dialog opened.
                self.remaining = self.remaining.saturating_sub(1);
            }
            self.queued
                .push_back(if failure { UiEvent::Enter } else { UiEvent::Escape });
            return Ok(());
        }
        self.busy = model.activity.is_some();
        let Mode::Approval(request) = &model.mode else {
            return Ok(());
        };
        if self.busy {
            return Ok(());
        }
        // The host-key question and the deployment dialog are separate steps
        // of the same request.
        let stage = if !request.host_mutations.is_empty() {
            if request.host_mutations_before_deploy { 1 } else { 3 }
        } else if request.host_key.is_some() { 0 } else { 2 };
        let step = (
            request.id.clone(),
            stage,
            request.host_mutation_token.clone(),
        );
        if self.answered.as_ref() == Some(&step) {
            if std::mem::take(&mut self.failed) {
                self.queued.push_back(UiEvent::Character('n'));
            }
            return Ok(());
        }
        for warning in &request.connection_warnings {
            println!("connection-warning: {}", warning.replace(['\n', '\r'], " | "));
        }
        println!(
            "dialog: {} host-key={} allow-partial={} create={:?} replace={:?} generate={:?} missing={:?} skippable={:?}",
            request.target,
            request.host_key.is_some(),
            request.allow_partial,
            request.create,
            request.replace,
            request.generate,
            request.missing,
            request.skippable
        );
        self.answered = Some(step);
        if !request.host_mutations.is_empty() {
            println!(
                "host-value-review: source={} replacements={}",
                request.target,
                request.host_mutations.len()
            );
            self.queued
                .push_back(UiEvent::Character(self.host_value_answer));
            return Ok(());
        }
        if request.host_key.is_some() {
            self.queued.push_back(UiEvent::Character('y'));
            return Ok(());
        }
        if self.answer == 'p' && !request.allow_partial {
            self.queued.push_back(UiEvent::Character('p'));
        }
        self.queued.push_back(UiEvent::Character(if self.answer == 'n' {
            'n'
        } else {
            'y'
        }));
        Ok(())
    }

    fn read(&mut self, timeout: Duration) -> io::Result<UiEvent> {
        if let Some(event) = self.queued.pop_front() {
            return Ok(event);
        }
        if self.remaining == 0 && !self.busy {
            // Esc in the tree quits.
            return Ok(UiEvent::Escape);
        }
        std::thread::sleep(timeout);
        Ok(UiEvent::Tick)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nix-secrets-test-operator: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse()?;
    let schema = Schema::from_json(&std::fs::read_to_string(&options.schema)?)?;
    let (backend, route, _remote_connection) = if let Some(remote) = &options.remote {
        let ssh_arguments = vec![
            "-T".into(), "-o".into(), "BatchMode=yes".into(), "-o".into(), "StrictHostKeyChecking=yes".into(),
            "-i".into(), options.identity.clone().into_os_string(), "-o".into(),
            format!("UserKnownHostsFile={}",options.known_hosts.display()).into(),
            remote.destination.clone().into(),
        ];
        let (connection,route) = nix_secrets_manager::startup::connect_remote(
            &remote.repository,&ssh_arguments,&options.socket,&remote.socket,&remote.control,Duration::from_secs(60))?;
        (BackendClient::new(connection.stream.try_clone()?),Some(route),Some(connection))
    } else { (BackendClient::new(connect_verified(&options.socket)?),None,None) };
    let controller = Controller::new(
        backend,
        schema,
        match &options.launcher {
            // The 1Password provider, as the TUI runs it; the test's `op`
            // serves the identity as the one SSH key item.
            Some(launcher) => {
                AgeCommandProvider::default().through(launcher, vec!["--shared-session".into()])
            }
            None => AgeCommandProvider::identity_file(&options.identity),
        },
        vec![options.known_hosts.clone()],
    )?;
    let mut controller = controller;
    if let Some(route) = route { controller.set_backend_route(route); }
    for (identifier, value) in &options.set {
        nix_secrets_manager::ui::SecretWriter::write(
            &mut controller,
            identifier,
            zeroize::Zeroizing::new(value.as_bytes().to_vec()),
        )
        .map_err(|(error, _)| format!("cannot store {identifier}: {error}"))?;
        println!("stored {identifier}");
    }
    let rows = controller.rows()?;
    let mut writer = AsyncWriter::spawn(controller, options.socket.clone());
    let mut frontend = Scripted {
        answer: options.answer,
        host_value_answer: options.host_value_answer,
        remaining: options.requests,
        queued: VecDeque::new(),
        answered: None,
        failed: false,
        busy: false,
    };
    // Ready: `nix-secrets deploy` can now reach a registered frontend.
    println!("ready");
    drive(&mut frontend, &mut writer, &mut Model::new(rows))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_secrets_manager::model::{ApprovalRequest, HostMutationReview};
    #[test]
    fn deployment_consent_does_not_implicitly_consent_to_host_replacements() {
        let mut scripted = Scripted {
            answer: 'y',
            host_value_answer: 'n',
            remaining: 1,
            queued: VecDeque::new(),
            answered: None,
            failed: false,
            busy: false,
        };
        let mut model = Model::new(vec![]);
        let normal = ApprovalRequest {
            id: "same".into(),
            target: "producer".into(),
            ..Default::default()
        };
        model.mode = Mode::Approval(normal.clone());
        scripted.draw(&model).unwrap();
        assert_eq!(scripted.queued.pop_front(), Some(UiEvent::Character('y')));
        let mut review = normal;
        review.host_mutation_token = Some("new-phase".into());
        review.host_mutations.push(HostMutationReview {
            identifier: "receiver.known-hosts".into(),
            kind: "receiver host identity".into(),
            previous: vec!["SHA256:old".into()],
            proposed: vec!["SHA256:new".into()],
        });
        model.mode = Mode::Approval(review);
        scripted.draw(&model).unwrap();
        assert_eq!(scripted.queued.pop_front(), Some(UiEvent::Character('n')));
        assert_eq!(
            scripted.remaining, 1,
            "request is unfinished until replacement phase resolves"
        );
    }
}
