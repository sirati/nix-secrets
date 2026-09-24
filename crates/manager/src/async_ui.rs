use crate::controller::Controller;
use crate::model::ApprovalRequest;
use crate::tree::Row;
use crate::ui::{Action, Completion, GenerateKind, SecretWriter};
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
    Approval(bool),
}

enum Event {
    Rows(Vec<Row>),
    Approval(ApprovalRequest),
    Completion(Completion),
    Error(String),
    ApprovalLost(String),
}

pub struct AsyncWriter {
    commands: Sender<Command>,
    events: Receiver<Event>,
    rows: Option<Vec<Row>>,
    approvals: Vec<ApprovalRequest>,
    completions: Vec<Completion>,
    busy: bool,
}

impl AsyncWriter {
    pub fn spawn(mut controller: Controller, socket: PathBuf) -> Self {
        let (commands, incoming) = mpsc::channel();
        let (outgoing, events) = mpsc::channel();
        std::thread::spawn(move || {
            controller.start_background_refresh(socket);
            loop {
                match incoming.recv_timeout(Duration::from_millis(25)) {
                    Ok(command) => {
                        let completion = execute(&mut controller, command);
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
            approvals: vec![],
            completions: vec![],
            busy: false,
        }
    }

    fn pump(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Rows(rows) => self.rows = Some(rows),
                Event::Approval(request) => self.approvals.push(request),
                Event::Completion(result) => {
                    self.busy = false;
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
        self.commands
            .send(command)
            .map_err(|_| "backend worker stopped".to_string())?;
        self.busy = true;
        Ok(())
    }
}

fn execute(controller: &mut Controller, command: Command) -> Completion {
    match command {
        Command::Write { path, value } => match controller.write(&path, value) {
            Ok(Action::Saved(path)) => Completion::Saved(path),
            Ok(_) => Completion::Failed("save did not complete".into()),
            Err((message, value)) => Completion::SaveFailed {
                path,
                value,
                message,
            },
        },
        Command::Delete(path) => match controller.delete(&path) {
            Ok(()) => Completion::Deleted(path),
            Err(error) => Completion::Failed(error),
        },
        Command::Reveal(path) => match controller.reveal(&path) {
            Ok(value) => Completion::Revealed { path, value },
            Err(error) => Completion::Failed(error),
        },
        Command::CopyPublic(path) => match controller.copy_public(&path) {
            Ok(()) => Completion::Copied(format!("copied public key for {path}")),
            Err(error) => Completion::Failed(error),
        },
        Command::CopyValue(value) => match controller.copy(&value) {
            Ok(()) => Completion::Copied("value copied".into()),
            Err(error) => Completion::Failed(error),
        },
        Command::Generate {
            path,
            kind,
            replacing,
        } => match controller.generate(&path, kind) {
            Ok(value) => Completion::Generated {
                path,
                value,
                replacing,
            },
            Err(error) => Completion::Failed(error),
        },
        Command::Approval(accepted) => match controller.approval(accepted) {
            Ok(next) => Completion::ApprovalDone(next),
            Err(error) => Completion::Failed(error),
        },
    }
}

impl SecretWriter for AsyncWriter {
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
        Err(format!("deleting {path}..."))
    }

    fn reveal(&mut self, path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        self.queue(Command::Reveal(path.into()))?;
        Err(format!("decrypting {path}..."))
    }

    fn copy_public(&mut self, path: &str) -> Result<(), String> {
        self.queue(Command::CopyPublic(path.into()))?;
        Err(format!("copying public key for {path}..."))
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
        Err(format!("generating value for {path}..."))
    }

    fn approval(&mut self, accepted: bool) -> Result<Option<ApprovalRequest>, String> {
        self.queue(Command::Approval(accepted))?;
        Err("processing deployment request...".into())
    }

    fn copy(&mut self, value: &[u8]) -> Result<(), String> {
        self.queue(Command::CopyValue(Zeroizing::new(value.to_vec())))?;
        Err("copying value...".into())
    }
}

#[cfg(test)]
mod tests;
