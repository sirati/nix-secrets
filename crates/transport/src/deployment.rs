use crate::{Frame, FrameError, FrameKind, SshError, SshSession, MAX_FRAME_BYTES};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read, Write};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub const DEPLOYMENT_PROTOCOL_VERSION: u16 = 1;
pub const MAX_DEPLOYMENT_JSON: usize = 64 * 1024 * 1024;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub path: String,
    pub category: String,
    pub owner: String,
    pub group: String,
    pub mode: String,
    #[serde(default)]
    pub consumer_units: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSecret {
    pub identifier: String,
    pub recipient_ids: Vec<String>,
    pub destination: Destination,
    pub current_version_id: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetState {
    pub protocol_version: u16,
    pub hostname: String,
    pub secrets: Vec<TargetSecret>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedSecret {
    pub identifier: String,
    pub recipient_ids: Vec<String>,
    pub destination: Destination,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedTarget {
    pub hostname: String,
    pub secrets: Vec<ExpectedSecret>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSelection {
    pub identifiers: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DeployEntry {
    pub identifier: String,
    pub version_id: String,
    pub contents_base64: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DeploymentBatch {
    pub version: u16,
    pub requested_identifiers: Vec<String>,
    pub entries: Vec<DeployEntry>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DeploymentResult {
    Applied { versions: BTreeMap<String, String> },
    Rejected { message: String },
}

#[derive(Debug)]
pub enum DeploymentError {
    Ssh(SshError),
    Protocol(FrameError),
    Json(serde_json::Error),
    Io(io::Error),
    Invalid(&'static str),
    Rejected,
}
impl fmt::Display for DeploymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssh(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
            Self::Json(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
            Self::Io(error) => error.fmt(f),
            Self::Rejected => f.write_str("target rejected deployment"),
        }
    }
}
impl std::error::Error for DeploymentError {}
impl From<SshError> for DeploymentError {
    fn from(value: SshError) -> Self {
        Self::Ssh(value)
    }
}
impl From<FrameError> for DeploymentError {
    fn from(value: FrameError) -> Self {
        Self::Protocol(value)
    }
}
impl From<serde_json::Error> for DeploymentError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
impl From<io::Error> for DeploymentError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

trait FrameIo {
    fn send_frame(&mut self, frame: Frame) -> Result<(), DeploymentError>;
    fn receive_frame(&mut self) -> Result<Frame, DeploymentError>;
}
impl FrameIo for SshSession {
    fn send_frame(&mut self, frame: Frame) -> Result<(), DeploymentError> {
        if frame.kind != FrameKind::Data {
            return Err(DeploymentError::Invalid("deployment uses data frames"));
        }
        self.send(&frame.payload).map_err(Into::into)
    }
    fn receive_frame(&mut self) -> Result<Frame, DeploymentError> {
        self.receive().map_err(Into::into)
    }
}

pub struct DeploymentClient<'a> {
    transport: &'a mut dyn FrameIo,
    state: Option<TargetState>,
}

pub struct PreparedDeployment {
    session: SshSession,
    state: TargetState,
}

impl PreparedDeployment {
    pub fn open(
        mut session: SshSession,
        expected: &ExpectedTarget,
    ) -> Result<Self, DeploymentError> {
        session.open(FrameKind::OpenDeployer)?;
        let identifiers = expected
            .secrets
            .iter()
            .map(|secret| secret.identifier.clone())
            .collect::<Vec<_>>();
        validate_selection(&identifiers)?;
        send_transport_json(&mut session, &DeploymentSelection { identifiers })?;
        let state: TargetState = receive_transport_json(&mut session)?;
        validate_target(&state, expected)?;
        Ok(Self { session, state })
    }

    pub fn state(&self) -> &TargetState {
        &self.state
    }

    pub fn deploy(
        mut self,
        entries: Vec<DeployEntry>,
    ) -> Result<DeploymentResult, DeploymentError> {
        let requested_identifiers = entries
            .iter()
            .map(|entry| entry.identifier.clone())
            .collect::<Vec<_>>();
        validate_entries(&entries, &requested_identifiers, &self.state.secrets)?;
        send_transport_json(
            &mut self.session,
            &DeploymentBatch {
                version: 1,
                requested_identifiers,
                entries,
            },
        )?;
        let result: DeploymentResult = receive_transport_json(&mut self.session)?;
        self.session.close_write()?;
        if matches!(result, DeploymentResult::Rejected { .. }) {
            return Err(DeploymentError::Rejected);
        }
        Ok(result)
    }
}

impl<'a> DeploymentClient<'a> {
    pub fn new(session: &'a mut SshSession) -> Self {
        Self {
            transport: session,
            state: None,
        }
    }

    pub fn receive_and_validate(
        &mut self,
        expected: &ExpectedTarget,
    ) -> Result<&TargetState, DeploymentError> {
        let identifiers = expected
            .secrets
            .iter()
            .map(|secret| secret.identifier.clone())
            .collect::<Vec<_>>();
        validate_selection(&identifiers)?;
        send_transport_json(self.transport, &DeploymentSelection { identifiers })?;
        let state: TargetState = receive_transport_json(self.transport)?;
        validate_target(&state, expected)?;
        self.state = Some(state);
        Ok(self.state.as_ref().expect("state was inserted"))
    }

    pub fn deploy(
        &mut self,
        entries: Vec<DeployEntry>,
    ) -> Result<DeploymentResult, DeploymentError> {
        let state = self
            .state
            .as_ref()
            .ok_or(DeploymentError::Invalid("target state was not validated"))?;
        let requested_identifiers = entries
            .iter()
            .map(|entry| entry.identifier.clone())
            .collect::<Vec<_>>();
        validate_entries(&entries, &requested_identifiers, &state.secrets)?;
        send_transport_json(
            self.transport,
            &DeploymentBatch {
                version: 1,
                requested_identifiers,
                entries,
            },
        )?;
        let result: DeploymentResult = receive_transport_json(self.transport)?;
        if matches!(result, DeploymentResult::Rejected { .. }) {
            return Err(DeploymentError::Rejected);
        }
        Ok(result)
    }
}

fn send_transport_json(
    transport: &mut dyn FrameIo,
    value: &impl Serialize,
) -> Result<(), DeploymentError> {
    let wire = Zeroizing::new(encode_json(value)?);
    for chunk in wire.chunks(MAX_FRAME_BYTES) {
        transport.send_frame(Frame {
            kind: FrameKind::Data,
            payload: chunk.to_vec(),
        })?;
    }
    Ok(())
}
fn receive_transport_json<T: DeserializeOwned>(
    transport: &mut dyn FrameIo,
) -> Result<T, DeploymentError> {
    let mut wire = Vec::new();
    loop {
        let frame = transport.receive_frame()?;
        if frame.kind != FrameKind::Data {
            return Err(DeploymentError::Invalid("expected deployment data frame"));
        }
        if wire.len().saturating_add(frame.payload.len()) > MAX_DEPLOYMENT_JSON + 4 {
            return Err(DeploymentError::Invalid("deployment message too large"));
        }
        wire.extend_from_slice(&frame.payload);
        if wire.len() >= 4 {
            let length = u32::from_be_bytes(wire[..4].try_into().expect("fixed length")) as usize;
            if length > MAX_DEPLOYMENT_JSON {
                return Err(DeploymentError::Invalid("deployment message too large"));
            }
            if wire.len() == length + 4 {
                return Ok(serde_json::from_slice(&wire[4..])?);
            }
            if wire.len() > length + 4 {
                return Err(DeploymentError::Invalid(
                    "multiple deployment messages in frame stream",
                ));
            }
        }
    }
}

mod server;
#[cfg(test)]
use server::select_state;
use server::{encode_json, validate_entries, validate_selection, validate_target};
pub use server::{read_wire_json, serve_deployment, write_wire_json};

#[cfg(test)]
mod tests;
