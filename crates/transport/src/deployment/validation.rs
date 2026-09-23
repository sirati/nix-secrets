use super::task_schema::validate_task_spec;
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
const MAX_PASSWORD_BYTES: usize = 64 * 1024;

pub(super) fn validate_server_state(state: &TargetState) -> Result<(), DeploymentError> {
    if state.protocol_version != DEPLOYMENT_PROTOCOL_VERSION || state.hostname.is_empty() {
        return Err(DeploymentError::Invalid("invalid target state"));
    }
    map_target_secrets(&state.secrets)?;
    map_target_tasks(&state.tasks).map(|_| ())
}

pub(super) fn select_state(
    state: &TargetState,
    selection: &DeploymentSelection,
) -> Result<TargetState, DeploymentError> {
    validate_selection(selection)?;
    let secrets = select(&state.secrets, &selection.identifiers, |item| {
        &item.identifier
    })?;
    let tasks = select(&state.tasks, &selection.task_identifiers, |item| {
        &item.identifier
    })?;
    Ok(TargetState {
        protocol_version: state.protocol_version,
        hostname: state.hostname.clone(),
        secrets,
        tasks,
    })
}

fn select<T: Clone>(
    available: &[T],
    identifiers: &[String],
    identifier: impl Fn(&T) -> &String,
) -> Result<Vec<T>, DeploymentError> {
    let wanted: BTreeSet<&str> = identifiers.iter().map(String::as_str).collect();
    let selected = available
        .iter()
        .filter(|item| wanted.contains(identifier(item).as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if selected.len() != wanted.len() {
        Err(DeploymentError::Invalid(
            "selection is absent from target schema",
        ))
    } else {
        Ok(selected)
    }
}

pub(super) fn validate_selection(selection: &DeploymentSelection) -> Result<(), DeploymentError> {
    if selection.identifiers.is_empty() && selection.task_identifiers.is_empty() {
        return Err(DeploymentError::Invalid("deployment subset is empty"));
    }
    unique_identifiers(&selection.identifiers, "duplicate selected secret")?;
    unique_identifiers(&selection.task_identifiers, "duplicate selected task")?;
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
    if map_target_secrets(&state.secrets)? != map_expected_secrets(&expected.secrets)? {
        return Err(DeploymentError::Invalid("target secret schema mismatch"));
    }
    if map_target_tasks(&state.tasks)? != map_expected_tasks(&expected.tasks)? {
        return Err(DeploymentError::Invalid("target task schema mismatch"));
    }
    Ok(())
}
type SecretSpec = (Vec<String>, Destination, Option<PublicInfoAttestation>);
type TaskSpec = (
    String,
    Vec<String>,
    Destination,
    Option<StorageBoxBootstrap>,
);

fn map_target_secrets(
    items: &[TargetSecret],
) -> Result<BTreeMap<String, SecretSpec>, DeploymentError> {
    map_unique(items, |item| {
        (
            &item.identifier,
            (
                item.recipient_ids.clone(),
                item.destination.clone(),
                item.public_info.clone(),
            ),
        )
    })
}
fn map_expected_secrets(
    items: &[ExpectedSecret],
) -> Result<BTreeMap<String, SecretSpec>, DeploymentError> {
    map_unique(items, |item| {
        (
            &item.identifier,
            (
                item.recipient_ids.clone(),
                item.destination.clone(),
                item.public_info.clone(),
            ),
        )
    })
}
fn map_target_tasks(items: &[TargetTask]) -> Result<BTreeMap<String, TaskSpec>, DeploymentError> {
    for item in items {
        validate_task_spec(
            &item.identifier,
            &item.task_type,
            &item.output,
            &item.bootstrap,
        )?;
    }
    map_unique(items, |item| {
        (
            &item.identifier,
            task_spec(
                &item.task_type,
                &item.recipient_ids,
                &item.output,
                &item.bootstrap,
            ),
        )
    })
}
fn map_expected_tasks(
    items: &[ExpectedTask],
) -> Result<BTreeMap<String, TaskSpec>, DeploymentError> {
    for item in items {
        validate_task_spec(
            &item.identifier,
            &item.task_type,
            &item.output,
            &item.bootstrap,
        )?;
    }
    map_unique(items, |item| {
        (
            &item.identifier,
            task_spec(
                &item.task_type,
                &item.recipient_ids,
                &item.output,
                &item.bootstrap,
            ),
        )
    })
}
fn task_spec(
    kind: &str,
    recipients: &[String],
    output: &Destination,
    bootstrap: &Option<StorageBoxBootstrap>,
) -> TaskSpec {
    (
        kind.into(),
        recipients.to_vec(),
        output.clone(),
        bootstrap.clone(),
    )
}

fn map_unique<T, V>(
    items: &[T],
    item: impl Fn(&T) -> (&String, V),
) -> Result<BTreeMap<String, V>, DeploymentError> {
    let mut result = BTreeMap::new();
    for value in items {
        let (identifier, spec) = item(value);
        validate_identifier(identifier)?;
        if result.insert(identifier.clone(), spec).is_some() {
            return Err(DeploymentError::Invalid("duplicate target identifier"));
        }
    }
    Ok(result)
}

pub(super) fn validate_batch(
    batch: &DeploymentBatch,
    state: &TargetState,
) -> Result<(), DeploymentError> {
    validate_entries(&batch.entries, &batch.requested_identifiers, &state.secrets)?;
    validate_tasks(&batch.tasks, &batch.requested_tasks, &state.tasks)
}

fn validate_entries(
    entries: &[DeployEntry],
    requested: &[String],
    available: &[TargetSecret],
) -> Result<(), DeploymentError> {
    validate_supplied(
        requested,
        entries.iter().map(|item| &item.identifier),
        available.iter().map(|item| &item.identifier),
    )?;
    if entries
        .iter()
        .any(|item| !valid_version(&item.version_id) || item.contents_base64.is_empty())
    {
        return Err(DeploymentError::Invalid("invalid deployment entry"));
    }
    Ok(())
}

fn validate_tasks(
    entries: &[TaskEntry],
    requested: &[String],
    available: &[TargetTask],
) -> Result<(), DeploymentError> {
    validate_supplied(
        requested,
        entries.iter().map(|item| &item.identifier),
        available.iter().map(|item| &item.identifier),
    )?;
    for entry in entries {
        if !valid_version(&entry.version_id) {
            return Err(DeploymentError::Invalid("invalid task version"));
        }
        let password = Zeroizing::new(
            STANDARD
                .decode(&entry.password_base64)
                .map_err(|_| DeploymentError::Invalid("invalid task password encoding"))?,
        );
        let local_key = available
            .iter()
            .any(|task| task.identifier == entry.identifier && task.task_type == LOCAL_SSH_KEY);
        if (!local_key && password.is_empty())
            || (local_key && !password.is_empty())
            || password.len() > MAX_PASSWORD_BYTES
        {
            return Err(DeploymentError::Invalid("invalid task password length"));
        }
        let contribution = Zeroizing::new(
            STANDARD
                .decode(&entry.client_contribution_base64)
                .map_err(|_| DeploymentError::Invalid("invalid client contribution encoding"))?,
        );
        if contribution.len() != 32 {
            return Err(DeploymentError::Invalid(
                "client contribution must be exactly 32 bytes",
            ));
        }
    }
    Ok(())
}

fn validate_supplied<'a>(
    requested: &[String],
    supplied: impl Iterator<Item = &'a String>,
    available: impl Iterator<Item = &'a String>,
) -> Result<(), DeploymentError> {
    let requested = unique_identifiers(requested, "duplicate requested identifier")?;
    let supplied = supplied.map(String::as_str).collect::<BTreeSet<_>>();
    let available = available.map(String::as_str).collect::<BTreeSet<_>>();
    if supplied.len() != requested.len() || supplied != requested {
        return Err(DeploymentError::Invalid(
            "entries do not match requested subset",
        ));
    }
    if !requested.is_subset(&available) {
        return Err(DeploymentError::Invalid(
            "requested identifier is absent from target schema",
        ));
    }
    Ok(())
}

pub(super) fn require_same_set(
    left: &[String],
    right: &[String],
    message: &'static str,
) -> Result<(), DeploymentError> {
    if left.iter().collect::<BTreeSet<_>>() == right.iter().collect::<BTreeSet<_>>() {
        Ok(())
    } else {
        Err(DeploymentError::Invalid(message))
    }
}
fn unique_identifiers<'a>(
    values: &'a [String],
    duplicate: &'static str,
) -> Result<BTreeSet<&'a str>, DeploymentError> {
    let mut result = BTreeSet::new();
    for value in values {
        validate_identifier(value)?;
        if !result.insert(value.as_str()) {
            return Err(DeploymentError::Invalid(duplicate));
        }
    }
    Ok(result)
}
fn valid_version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256
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
