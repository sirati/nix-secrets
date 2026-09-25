use crate::controller::Controller;
use crate::model::ApprovalRequest;
use crate::tree::Row;
use crate::ui::{Action, Completion, GenerateKind, SecretWriter, OPERATION_QUEUED};
use nix_secrets_core::{ProfileSnapshot, ViewProfile};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;
use zeroize::Zeroizing;

enum Command {
    Write {
        path: String,
        value: Zeroizing<Vec<u8>>,
    },
    Delete(String),
    Reveal(String),
    CopyPublic(String),
    CopyValue(Zeroizing<Vec<u8>>),
    Generate {
        path: String,
        kind: GenerateKind,
        replacing: bool,
    },
    BulkGenerate {
        paths: Vec<String>,
        kind: GenerateKind,
    },
    Approval(bool),
    SaveProfile {
        name: String,
        profile: ViewProfile,
        revision: u64,
    },
    DeleteProfile {
        name: String,
        revision: u64,
    },
}

enum Event {
    Rows(Vec<Row>),
    Profiles(ProfileSnapshot),
    Approval(ApprovalRequest),
    Completion(Completion),
    Error(String),
    ApprovalLost(String),
}

pub struct AsyncWriter {
    commands: Sender<Command>,
    events: Receiver<Event>,
    rows: Option<Vec<Row>>,
    profiles: Option<ProfileSnapshot>,
    approvals: Vec<ApprovalRequest>,
    completions: Vec<Completion>,
    busy: bool,
    activity: Option<crate::model::Activity>,
    /// Whether decryption goes through 1Password and may wait for approval.
    one_password: bool,
}

impl AsyncWriter {
    pub fn spawn(mut controller: Controller, socket: PathBuf) -> Self {
        let one_password = controller.uses_one_password();
        let (commands, incoming) = mpsc::channel();
        let (outgoing, events) = mpsc::channel();
        std::thread::spawn(move || {
            controller.start_background_refresh(socket);
            loop {
                match incoming.recv_timeout(Duration::from_millis(25)) {
                    Ok(command) => {
                        let completion = match command {
                            Command::BulkGenerate { paths, kind } => {
                                execute_bulk(&mut controller, paths, kind, &outgoing)
                            }
                            other => execute(&mut controller, other),
                        };
                        if outgoing.send(Event::Completion(completion)).is_err() {
                            return;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                match controller.refresh_rows() {
                    Ok(Some(rows)) => {
                        if outgoing.send(Event::Rows(rows)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if outgoing.send(Event::Error(error)).is_err() {
                            return;
                        }
                    }
                }
                match controller.refresh_profiles() {
                    Ok(Some(snapshot)) => {
                        if outgoing.send(Event::Profiles(snapshot)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if outgoing.send(Event::Error(error)).is_err() {
                            return;
                        }
                    }
                }
                match controller.poll_approval() {
                    Ok(Some(request)) => {
                        if outgoing.send(Event::Approval(request)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if outgoing.send(Event::ApprovalLost(error)).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        Self {
            commands,
            events,
            rows: None,
            profiles: None,
            approvals: vec![],
            completions: vec![],
            busy: false,
            activity: None,
            one_password,
        }
    }

    fn pump(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Rows(rows) => self.rows = Some(rows),
                Event::Profiles(snapshot) => self.profiles = Some(snapshot),
                Event::Approval(request) => self.approvals.push(request),
                Event::Completion(result) => {
                    if !matches!(result, Completion::BulkProgress { .. }) {
                        self.busy = false;
                        self.activity = None;
                    }
                    self.completions.push(result);
                }
                Event::Error(error) => self.completions.push(Completion::Failed(error)),
                Event::ApprovalLost(error) => {
                    self.completions.push(Completion::ApprovalLost(error))
                }
            }
        }
    }

    fn queue(&mut self, command: Command) -> Result<(), String> {
        if self.busy {
            return Err("another operation is still running".into());
        }
        let activity = describe(&command, self.one_password);
        self.commands
            .send(command)
            .map_err(|_| "backend worker stopped".to_string())?;
        self.busy = true;
        self.activity = activity;
        Ok(())
    }
}

mod execute;
use execute::execute;

mod bulk;
use bulk::execute_bulk;

impl SecretWriter for AsyncWriter {
    fn refresh_profiles(&mut self) -> Result<Option<ProfileSnapshot>, String> {
        self.pump();
        Ok(self.profiles.take())
    }
    fn save_profile(
        &mut self,
        name: String,
        profile: ViewProfile,
        revision: u64,
    ) -> Result<ProfileSnapshot, String> {
        self.queue(Command::SaveProfile {
            name,
            profile,
            revision,
        })?;
        Err(OPERATION_QUEUED.into())
    }
    fn delete_profile(&mut self, name: String, revision: u64) -> Result<ProfileSnapshot, String> {
        self.queue(Command::DeleteProfile { name, revision })?;
        Err(OPERATION_QUEUED.into())
    }
    fn poll_completion(&mut self) -> Option<Completion> {
        self.pump();
        if self.completions.is_empty() {
            None
        } else {
            Some(self.completions.remove(0))
        }
    }

    fn refresh_rows(&mut self) -> Result<Option<Vec<Row>>, String> {
        self.pump();
        Ok(self.rows.take())
    }

    fn poll_approval(&mut self) -> Result<Option<ApprovalRequest>, String> {
        self.pump();
        if self.approvals.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.approvals.remove(0)))
        }
    }

    fn write(
        &mut self,
        path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        if self.busy {
            return Err(("another operation is still running".into(), value));
        }
        match self.commands.send(Command::Write {
            path: path.into(),
            value,
        }) {
            Ok(()) => {
                self.busy = true;
                self.activity = Some(activity(
                    format!("Encrypting and saving {path}"),
                    self.one_password,
                ));
                Ok(Action::Queued)
            }
            Err(mpsc::SendError(Command::Write { value, .. })) => {
                Err(("backend worker stopped".into(), value))
            }
            Err(_) => unreachable!(),
        }
    }

    fn delete(&mut self, path: &str) -> Result<(), String> {
        self.queue(Command::Delete(path.into()))?;
        Err(OPERATION_QUEUED.into())
    }

    fn reveal(&mut self, path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        self.queue(Command::Reveal(path.into()))?;
        Err(OPERATION_QUEUED.into())
    }

    fn copy_public(&mut self, path: &str) -> Result<(), String> {
        self.queue(Command::CopyPublic(path.into()))?;
        Err(OPERATION_QUEUED.into())
    }

    fn generate(&mut self, path: &str, kind: GenerateKind) -> Result<Zeroizing<Vec<u8>>, String> {
        self.generate_for(path, kind, false)
    }

    fn generate_for(
        &mut self,
        path: &str,
        kind: GenerateKind,
        replacing: bool,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        self.queue(Command::Generate {
            path: path.into(),
            kind,
            replacing,
        })?;
        Err(OPERATION_QUEUED.into())
    }

    fn approval(&mut self, accepted: bool) -> Result<Option<ApprovalRequest>, String> {
        self.queue(Command::Approval(accepted))?;
        Err(OPERATION_QUEUED.into())
    }

    fn generate_missing(&mut self, paths: Vec<String>, kind: GenerateKind) -> Result<(), String> {
        self.queue(Command::BulkGenerate { paths, kind })
    }

    fn copy(&mut self, value: &[u8]) -> Result<(), String> {
        self.queue(Command::CopyValue(Zeroizing::new(value.to_vec())))?;
        Err(OPERATION_QUEUED.into())
    }

    fn activity(&mut self) -> Option<crate::model::Activity> {
        self.pump();
        self.activity.clone()
    }
}

fn activity(label: String, waits_for_one_password: bool) -> crate::model::Activity {
    crate::model::Activity {
        label,
        waits_for_one_password,
        started: std::time::Instant::now(),
    }
}

/// Names the slow commands; quick clipboard and profile edits show nothing.
fn describe(command: &Command, one_password: bool) -> Option<crate::model::Activity> {
    let (label, decrypts) = match command {
        Command::Reveal(path) => (format!("Decrypting {path}"), true),
        Command::Approval(true) => ("Decrypting values for deployment".into(), true),
        Command::Approval(false) => ("Rejecting deployment request".into(), false),
        // Saving verifies private keys and task values by decrypting them.
        Command::Write { path, .. } => (format!("Encrypting and saving {path}"), true),
        Command::Delete(path) => (format!("Deleting {path}"), false),
        Command::Generate { path, .. } => (format!("Generating {path}"), false),
        Command::BulkGenerate { paths, .. } => (
            format!("Generating {} missing passwords", paths.len()),
            false,
        ),
        Command::CopyPublic(_)
        | Command::CopyValue(_)
        | Command::SaveProfile { .. }
        | Command::DeleteProfile { .. } => return None,
    };
    Some(activity(label, decrypts && one_password))
}

#[cfg(test)]
mod tests;
