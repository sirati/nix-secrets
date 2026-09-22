use super::validation::{require_same_set, select_state, validate_batch, validate_server_state};
use super::*;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub fn serve_deployment<R, W, F>(
    mut input: R,
    mut output: W,
    state: TargetState,
    apply: F,
) -> Result<(), DeploymentError>
where
    R: Read,
    W: Write,
    F: FnOnce(DeploymentBatch) -> Result<BTreeMap<String, String>, String>,
{
    validate_server_state(&state)?;
    let selection: DeploymentSelection = read_wire_json(&mut input)?;
    let selected_state = select_state(&state, &selection)?;
    write_wire_json(&mut output, &selected_state)?;
    let batch: DeploymentBatch = read_wire_json(&mut input)?;
    if batch.version != DEPLOYMENT_PROTOCOL_VERSION {
        return Err(DeploymentError::Invalid(
            "unsupported deployment batch version",
        ));
    }
    require_same_set(
        &selection.identifiers,
        &batch.requested_identifiers,
        "batch secret subset differs from selection",
    )?;
    require_same_set(
        &selection.task_identifiers,
        &batch.requested_tasks,
        "batch task subset differs from selection",
    )?;
    validate_batch(&batch, &selected_state)?;
    let result = match apply(batch) {
        Ok(versions) => DeploymentResult::Applied { versions },
        Err(message) => DeploymentResult::Rejected { message },
    };
    write_wire_json(&mut output, &result)
}

pub fn read_wire_json<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, DeploymentError> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_DEPLOYMENT_JSON {
        return Err(DeploymentError::Invalid("deployment message too large"));
    }
    let mut body = Zeroizing::new(vec![0_u8; length]);
    reader.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

pub fn write_wire_json(
    writer: &mut impl Write,
    value: &impl Serialize,
) -> Result<(), DeploymentError> {
    let wire = Zeroizing::new(encode_json(value)?);
    writer.write_all(&wire)?;
    writer.flush()?;
    Ok(())
}

pub(super) fn encode_json(value: &impl Serialize) -> Result<Vec<u8>, DeploymentError> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_DEPLOYMENT_JSON {
        return Err(DeploymentError::Invalid("deployment message too large"));
    }
    let mut wire = Vec::with_capacity(body.len() + 4);
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
    wire.extend_from_slice(&body);
    Ok(wire)
}
