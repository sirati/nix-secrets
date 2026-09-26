use super::validation::{require_same_set, select_state, validate_batch, validate_server_state};
use super::*;
use serde::{de::DeserializeOwned, Serialize};
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
    F: FnOnce(DeploymentBatch) -> Result<AppliedOutput, String>,
{
    validate_server_state(&state)?;
    let selection: DeploymentSelection = read_wire_json(&mut input)?;
    let selected_state = select_state(&state, &selection)?;
    write_wire_json(&mut output, &selected_state)?;
    let batch: DeploymentBatch = read_wire_json(&mut input)?;
    if !matches!(
        batch.version,
        LEGACY_DEPLOYMENT_PROTOCOL_VERSION | DEPLOYMENT_PROTOCOL_VERSION
    ) {
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
    // A version 1 client sends version 1 batches, which carry no generation.
    let mut batch_state = selected_state.clone();
    batch_state.protocol_version = batch.version;
    validate_batch(&batch, &batch_state)?;
    let generate = batch
        .generate
        .iter()
        .map(|item| item.identifier.clone())
        .collect::<Vec<_>>();
    let result = match apply(batch) {
        Ok(output)
            if output.generated_records.len() != generate.len()
                || generate
                    .iter()
                    .any(|id| !output.generated_records.contains_key(id)) =>
        {
            DeploymentResult::Rejected {
                message: "target did not return exactly the generated records".into(),
            }
        }
        Ok(output) => DeploymentResult::Applied {
            versions: output.versions,
            generated_public_keys: output.generated_public_keys,
            generated_records: output.generated_records,
        },
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
