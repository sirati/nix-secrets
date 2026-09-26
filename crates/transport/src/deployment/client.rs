use super::server::encode_json;
use super::validation::{validate_batch, validate_selection, validate_target, verify_generators};
use super::*;
use crate::{Frame, FrameKind, SshSession, MAX_FRAME_BYTES};
use serde::{de::DeserializeOwned, Serialize};
use zeroize::Zeroizing;

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
    expected: ExpectedTarget,
}

fn selection(expected: &ExpectedTarget) -> DeploymentSelection {
    DeploymentSelection {
        identifiers: expected
            .secrets
            .iter()
            .map(|item| item.identifier.clone())
            .collect(),
        task_identifiers: expected
            .tasks
            .iter()
            .map(|item| item.identifier.clone())
            .collect(),
    }
}

fn batch(
    version: u16,
    entries: Vec<DeployEntry>,
    tasks: Vec<TaskEntry>,
    generate: Vec<GenerateEntry>,
    derive: Vec<String>,
) -> DeploymentBatch {
    DeploymentBatch {
        version,
        requested_identifiers: entries
            .iter()
            .map(|item| item.identifier.clone())
            .chain(generate.iter().map(|item| item.identifier.clone()))
            .chain(derive.iter().cloned())
            .collect(),
        requested_tasks: tasks.iter().map(|item| item.identifier.clone()).collect(),
        entries,
        tasks,
        generate,
        derive,
    }
}

impl PreparedDeployment {
    pub fn open(
        mut session: SshSession,
        expected: &ExpectedTarget,
    ) -> Result<Self, DeploymentError> {
        session.open(FrameKind::OpenDeployer)?;
        let selected = selection(expected);
        validate_selection(&selected)?;
        send_transport_json(&mut session, &selected)?;
        let state: TargetState = receive_transport_json(&mut session)?;
        validate_target(&state, expected)?;
        Ok(Self {
            session,
            state,
            expected: expected.clone(),
        })
    }

    pub fn state(&self) -> &TargetState {
        &self.state
    }

    pub fn deploy(self, entries: Vec<DeployEntry>) -> Result<DeploymentResult, DeploymentError> {
        self.deploy_with_tasks(entries, Vec::new())
    }

    pub fn deploy_with_tasks(
        self,
        entries: Vec<DeployEntry>,
        tasks: Vec<TaskEntry>,
    ) -> Result<DeploymentResult, DeploymentError> {
        self.deploy_with_generation(entries, tasks, Vec::new(), Vec::new())
    }

    /// Whether the target can generate values (deployment protocol 2).
    pub fn supports_generation(&self) -> bool {
        self.state.protocol_version >= DEPLOYMENT_PROTOCOL_VERSION
    }

    pub fn deploy_with_generation(
        mut self,
        entries: Vec<DeployEntry>,
        tasks: Vec<TaskEntry>,
        generate: Vec<GenerateEntry>,
        derive: Vec<String>,
    ) -> Result<DeploymentResult, DeploymentError> {
        if (!generate.is_empty() || !derive.is_empty()) && !self.supports_generation() {
            return Err(DeploymentError::Invalid(
                "target runs deployment protocol 1 and cannot generate values; rebuild it first",
            ));
        }
        verify_generators(
            &self.state,
            &self.expected,
            &generate
                .iter()
                .map(|item| item.identifier.clone())
                .collect::<Vec<_>>(),
        )?;
        // `validate_target` already compared every leaf's derivation with the
        // operator's schema, so the target frames exactly as declared.
        let batch = batch(
            self.state.protocol_version,
            entries,
            tasks,
            generate,
            derive,
        );
        validate_batch(&batch, &self.state)?;
        send_transport_json(&mut self.session, &batch)?;
        let result: DeploymentResult = receive_transport_json(&mut self.session)?;
        self.session.close_write()?;
        reject_or_return(result)
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
        let selected = selection(expected);
        validate_selection(&selected)?;
        send_transport_json(self.transport, &selected)?;
        let state: TargetState = receive_transport_json(self.transport)?;
        validate_target(&state, expected)?;
        self.state = Some(state);
        Ok(self.state.as_ref().expect("state was inserted"))
    }

    pub fn deploy(
        &mut self,
        entries: Vec<DeployEntry>,
    ) -> Result<DeploymentResult, DeploymentError> {
        self.deploy_with_tasks(entries, Vec::new())
    }

    pub fn deploy_with_tasks(
        &mut self,
        entries: Vec<DeployEntry>,
        tasks: Vec<TaskEntry>,
    ) -> Result<DeploymentResult, DeploymentError> {
        let state = self
            .state
            .as_ref()
            .ok_or(DeploymentError::Invalid("target state was not validated"))?;
        let batch = batch(
            state.protocol_version,
            entries,
            tasks,
            Vec::new(),
            Vec::new(),
        );
        validate_batch(&batch, state)?;
        send_transport_json(self.transport, &batch)?;
        reject_or_return(receive_transport_json(self.transport)?)
    }
}

fn reject_or_return(result: DeploymentResult) -> Result<DeploymentResult, DeploymentError> {
    if matches!(result, DeploymentResult::Rejected { .. }) {
        Err(DeploymentError::Rejected)
    } else {
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
