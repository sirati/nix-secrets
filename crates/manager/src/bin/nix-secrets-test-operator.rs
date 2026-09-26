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
//! ```
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

struct Options {
    socket: PathBuf,
    schema: PathBuf,
    identity: PathBuf,
    known_hosts: PathBuf,
    answer: char,
    requests: usize,
    set: Vec<(String, String)>,
}

fn parse() -> Result<Options, String> {
    let mut arguments = std::env::args().skip(1);
    let (mut socket, mut schema, mut identity, mut known_hosts) = (None, None, None, None);
    let mut answer = 'y';
    let mut requests = 1;
    let mut set = Vec::new();
    while let Some(argument) = arguments.next() {
        let mut value = || arguments.next().ok_or(format!("{argument} requires a value"));
        match argument.as_str() {
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
            "--set" => {
                let assignment = value()?;
                let (identifier, text) = assignment
                    .split_once('=')
                    .ok_or("--set needs IDENTIFIER=VALUE")?;
                set.push((identifier.to_owned(), text.replace("\\n", "\n")));
            }
            "--requests" => requests = value()?.parse().map_err(|_| "--requests needs a number")?,
            other => return Err(format!("unexpected argument {other}")),
        }
    }
    Ok(Options {
        socket: socket.ok_or("--backend-socket is required")?,
        schema: schema.ok_or("--schema-file is required")?,
        identity: identity.ok_or("--secret-identity is required")?,
        known_hosts: known_hosts.ok_or("--known-hosts is required")?,
        answer,
        requests,
        set,
    })
}

/// Presses the operator's keys from what the model shows.
struct Scripted {
    answer: char,
    remaining: usize,
    queued: VecDeque<UiEvent>,
    /// The deployment request whose dialog was already answered.
    answered: Option<(String, bool)>,
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
        let step = (request.id.clone(), request.host_key.is_some());
        if self.answered.as_ref() == Some(&step) {
            if std::mem::take(&mut self.failed) {
                self.queued.push_back(UiEvent::Character('n'));
            }
            return Ok(());
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
    let controller = Controller::new(
        BackendClient::new(connect_verified(&options.socket)?),
        schema,
        AgeCommandProvider::identity_file(&options.identity),
        vec![options.known_hosts.clone()],
    )?;
    let mut controller = controller;
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
