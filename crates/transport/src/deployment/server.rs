use super::*;

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
    let selected_state = select_state(&state, &selection.identifiers)?;
    write_wire_json(&mut output, &selected_state)?;
    let batch: DeploymentBatch = read_wire_json(&mut input)?;
    if batch.version != 1 {
        return Err(DeploymentError::Invalid(
            "unsupported deployment batch version",
        ));
    }
    let selected: BTreeSet<&str> = selection.identifiers.iter().map(String::as_str).collect();
    let requested: BTreeSet<&str> = batch
        .requested_identifiers
        .iter()
        .map(String::as_str)
        .collect();
    if selected != requested {
        return Err(DeploymentError::Invalid(
            "batch does not match selected subset",
        ));
    }
    validate_entries(
        &batch.entries,
        &batch.requested_identifiers,
        &selected_state.secrets,
    )?;
    let result = match apply(batch) {
        Ok(versions) => DeploymentResult::Applied { versions },
        Err(message) => DeploymentResult::Rejected { message },
    };
    write_wire_json(&mut output, &result)?;
    Ok(())
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

fn validate_server_state(state: &TargetState) -> Result<(), DeploymentError> {
    if state.protocol_version != DEPLOYMENT_PROTOCOL_VERSION || state.hostname.is_empty() {
        return Err(DeploymentError::Invalid("invalid target state"));
    }
    map_target(&state.secrets).map(|_| ())
}

pub(super) fn select_state(
    state: &TargetState,
    identifiers: &[String],
) -> Result<TargetState, DeploymentError> {
    validate_selection(identifiers)?;
    let wanted: BTreeSet<&str> = identifiers.iter().map(String::as_str).collect();
    let secrets = state
        .secrets
        .iter()
        .filter(|secret| wanted.contains(secret.identifier.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if secrets.len() != wanted.len() {
        return Err(DeploymentError::Invalid(
            "selected secret is absent from target schema",
        ));
    }
    Ok(TargetState {
        protocol_version: state.protocol_version,
        hostname: state.hostname.clone(),
        secrets,
    })
}

pub(super) fn validate_selection(identifiers: &[String]) -> Result<(), DeploymentError> {
    if identifiers.is_empty() {
        return Err(DeploymentError::Invalid("deployment subset is empty"));
    }
    let mut unique = BTreeSet::new();
    for identifier in identifiers {
        validate_identifier(identifier)?;
        if !unique.insert(identifier) {
            return Err(DeploymentError::Invalid("duplicate selected secret"));
        }
    }
    Ok(())
}

pub(super) fn validate_target(
    state: &TargetState,
    expected: &ExpectedTarget,
) -> Result<(), DeploymentError> {
    if state.protocol_version != DEPLOYMENT_PROTOCOL_VERSION {
        return Err(DeploymentError::Invalid("unsupported deployment protocol"));
    }
    if state.hostname != expected.hostname {
        return Err(DeploymentError::Invalid("target hostname mismatch"));
    }
    let actual = map_target(&state.secrets)?;
    let wanted = map_expected(&expected.secrets)?;
    if actual != wanted {
        return Err(DeploymentError::Invalid("target schema mismatch"));
    }
    Ok(())
}

fn map_target(
    secrets: &[TargetSecret],
) -> Result<BTreeMap<String, (Vec<String>, Destination)>, DeploymentError> {
    let mut result = BTreeMap::new();
    for secret in secrets {
        validate_identifier(&secret.identifier)?;
        if result
            .insert(
                secret.identifier.clone(),
                (secret.recipient_ids.clone(), secret.destination.clone()),
            )
            .is_some()
        {
            return Err(DeploymentError::Invalid("duplicate target secret"));
        }
    }
    Ok(result)
}
fn map_expected(
    secrets: &[ExpectedSecret],
) -> Result<BTreeMap<String, (Vec<String>, Destination)>, DeploymentError> {
    let mut result = BTreeMap::new();
    for secret in secrets {
        validate_identifier(&secret.identifier)?;
        if result
            .insert(
                secret.identifier.clone(),
                (secret.recipient_ids.clone(), secret.destination.clone()),
            )
            .is_some()
        {
            return Err(DeploymentError::Invalid("duplicate expected secret"));
        }
    }
    Ok(result)
}
pub(super) fn validate_entries(
    entries: &[DeployEntry],
    requested: &[String],
    secrets: &[TargetSecret],
) -> Result<(), DeploymentError> {
    if requested.is_empty() {
        return Err(DeploymentError::Invalid("deployment subset is empty"));
    }
    let available: BTreeSet<&str> = secrets
        .iter()
        .map(|secret| secret.identifier.as_str())
        .collect();
    let mut expected = BTreeSet::new();
    for identifier in requested {
        validate_identifier(identifier)?;
        if !available.contains(identifier.as_str()) {
            return Err(DeploymentError::Invalid(
                "requested secret is absent from target schema",
            ));
        }
        if !expected.insert(identifier.as_str()) {
            return Err(DeploymentError::Invalid("duplicate requested secret"));
        }
    }
    let mut actual = BTreeSet::new();
    for entry in entries {
        validate_identifier(&entry.identifier)?;
        if entry.version_id.is_empty() || entry.contents_base64.is_empty() {
            return Err(DeploymentError::Invalid("empty deployment entry"));
        }
        if !actual.insert(entry.identifier.as_str()) {
            return Err(DeploymentError::Invalid("duplicate deployment entry"));
        }
    }
    if actual != expected {
        return Err(DeploymentError::Invalid(
            "deployment entries do not match requested subset",
        ));
    }
    Ok(())
}
fn validate_identifier(value: &str) -> Result<(), DeploymentError> {
    if value.is_empty()
        || value.len() > 4096
        || value
            .split('.')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        Err(DeploymentError::Invalid("invalid secret identifier"))
    } else {
        Ok(())
    }
}
