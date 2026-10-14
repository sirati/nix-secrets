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
    // The host's activation decides what it asks for. A selected value it
    // does not declare is reported back, and everything else still deploys.
    let mut absent = Vec::new();
    let secrets = select(&state.secrets, &selection.identifiers, |item| &item.identifier, &mut absent);
    let tasks = select(&state.tasks, &selection.task_identifiers, |item| &item.identifier, &mut absent);
    let selected = selection
        .identifiers
        .iter()
        .chain(&selection.task_identifiers)
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let unselected = state
        .secrets
        .iter()
        .map(|item| &item.identifier)
        .chain(state.tasks.iter().map(|item| &item.identifier))
        .filter(|identifier| !selected.contains(identifier.as_str()))
        .cloned()
        .collect();
    Ok(TargetState {
        protocol_version: state.protocol_version,
        hostname: state.hostname.clone(),
        secrets,
        tasks,
        absent,
        unselected,
    })
}

fn select<T: Clone>(
    available: &[T],
    identifiers: &[String],
    identifier: impl Fn(&T) -> &String,
    absent: &mut Vec<String>,
) -> Vec<T> {
    let wanted: BTreeSet<&str> = identifiers.iter().map(String::as_str).collect();
    let selected = available
        .iter()
        .filter(|item| wanted.contains(identifier(item).as_str()))
        .cloned()
        .collect::<Vec<_>>();
    absent.extend(
        identifiers
            .iter()
            .filter(|wanted| !selected.iter().any(|item| identifier(item) == *wanted))
            .cloned(),
    );
    selected
}

pub(super) fn validate_selection(selection: &DeploymentSelection) -> Result<(), DeploymentError> {
    if selection.identifiers.is_empty() && selection.task_identifiers.is_empty() {
        return Err(DeploymentError::Invalid("deployment subset is empty"));
    }
    unique_identifiers(&selection.identifiers, "duplicate selected secret")?;
    unique_identifiers(&selection.task_identifiers, "duplicate selected task")?;
    Ok(())
}

/// Accepts the target only if it declares every expected value exactly as
/// expected.
pub(super) fn validate_target(
    state: &TargetState,
    expected: &ExpectedTarget,
) -> Result<(), DeploymentError> {
    match compare_target(state, expected)?.first() {
        None => Ok(()),
        Some(left_out) => Err(DeploymentError::Mismatch(format!(
            "{}: {}",
            left_out.identifier, left_out.reason
        ))),
    }
}

/// The expected values the target does not declare, or declares otherwise:
/// they are left out, and the rest deploys. Only a target that is not the
/// expected host, or whose state is malformed, is refused.
pub fn compare_target(
    state: &TargetState,
    expected: &ExpectedTarget,
) -> Result<Vec<LeftOut>, DeploymentError> {
    if !matches!(
        state.protocol_version,
        LEGACY_DEPLOYMENT_PROTOCOL_VERSION..=DEPLOYMENT_PROTOCOL_VERSION
    ) {
        return Err(DeploymentError::Invalid("unsupported deployment protocol"));
    }
    if state.hostname != expected.hostname {
        return Err(DeploymentError::Invalid("target hostname mismatch"));
    }
    // Generator descriptions are compared only for values being generated,
    // see `verify_generators`, so an older target still receives set values.
    let mut left_out = Vec::new();
    compare(
        &map_target_secrets(&state.secrets)?,
        &state.absent,
        &map_expected_secrets(&expected.secrets)?,
        secret_difference,
        &mut left_out,
    )?;
    compare(
        &map_target_tasks(&state.tasks)?,
        &state.absent,
        &map_expected_tasks(&expected.tasks)?,
        task_difference,
        &mut left_out,
    )?;
    let wanted = expected
        .secrets
        .iter()
        .map(|item| &item.identifier)
        .chain(expected.tasks.iter().map(|item| &item.identifier))
        .collect::<BTreeSet<_>>();
    if let Some(extra) = state
        .secrets
        .iter()
        .map(|item| &item.identifier)
        .chain(state.tasks.iter().map(|item| &item.identifier))
        .chain(&state.absent)
        .find(|identifier| !wanted.contains(identifier))
    {
        return Err(DeploymentError::Mismatch(format!(
            "the target answered for {extra}, which was not selected"
        )));
    }
    Ok(left_out)
}

fn compare<V>(
    target: &BTreeMap<String, V>,
    absent: &[String],
    expected: &BTreeMap<String, V>,
    difference: fn(&V, &V) -> String,
    left_out: &mut Vec<LeftOut>,
) -> Result<(), DeploymentError> {
    for (identifier, want) in expected {
        match target.get(identifier) {
            // Only a target that says so leaves a selected value out.
            None if !absent.contains(identifier) => {
                return Err(DeploymentError::Mismatch(format!(
                    "target omitted {identifier} without listing it as absent"
                )))
            }
            None => left_out.push(LeftOut {
                identifier: identifier.clone(),
                absent: true,
                reason: "the host's current activation does not declare it".into(),
            }),
            Some(have) => {
                let difference = difference(have, want);
                if !difference.is_empty() {
                    left_out.push(LeftOut {
                        identifier: identifier.clone(),
                        absent: false,
                        reason: format!(
                            "the host's current activation declares it differently: {difference}"
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

fn differs<T: PartialEq + std::fmt::Debug>(
    out: &mut Vec<String>,
    what: &str,
    have: &T,
    want: &T,
) {
    if have != want {
        out.push(format!("{what} {have:?} on the host, {want:?} here"));
    }
}

fn destination_difference(out: &mut Vec<String>, have: &Destination, want: &Destination) {
    differs(out, "path", &have.path, &want.path);
    differs(out, "category", &have.category, &want.category);
    differs(out, "owner", &have.owner, &want.owner);
    differs(out, "group", &have.group, &want.group);
    differs(out, "mode", &have.mode, &want.mode);
    differs(out, "consumer units", &have.consumer_units, &want.consumer_units);
}

fn secret_difference(have: &SecretSpec, want: &SecretSpec) -> String {
    let mut out = Vec::new();
    differs(&mut out, "recipients", &have.0, &want.0);
    destination_difference(&mut out, &have.1, &want.1);
    differs(&mut out, "public-info attestation", &have.2, &want.2);
    differs(&mut out, "derivation", &have.3, &want.3);
    out.join("; ")
}

fn task_difference(have: &TaskSpec, want: &TaskSpec) -> String {
    let mut out = Vec::new();
    differs(&mut out, "task type", &have.0, &want.0);
    differs(&mut out, "recipients", &have.1, &want.1);
    destination_difference(&mut out, &have.2, &want.2);
    differs(&mut out, "Storage Box bootstrap", &have.3, &want.3);
    out.join("; ")
}
type SecretSpec = (
    Vec<String>,
    Destination,
    Option<PublicInfoAttestation>,
    Option<String>,
);
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
                item.derived.clone(),
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
                item.derived.clone(),
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
    if batch.version > state.protocol_version || batch.version < LEGACY_DEPLOYMENT_PROTOCOL_VERSION
    {
        return Err(DeploymentError::Invalid(
            "batch version is not supported by the target",
        ));
    }
    if batch.version == LEGACY_DEPLOYMENT_PROTOCOL_VERSION
        && (!batch.generate.is_empty() || !batch.derive.is_empty())
    {
        return Err(DeploymentError::Invalid(
            "deployment protocol 1 cannot generate values",
        ));
    }
    validate_entries(batch, &state.secrets)?;
    validate_tasks(&batch.tasks, &batch.requested_tasks, &state.tasks)
}

fn validate_entries(
    batch: &DeploymentBatch,
    available: &[TargetSecret],
) -> Result<(), DeploymentError> {
    let entries = &batch.entries;
    let supplied = unique_identifiers(
        &entries
            .iter()
            .map(|item| item.identifier.clone())
            .collect::<Vec<_>>(),
        "duplicate supplied identifier",
    )?
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if batch.version < SHARED_SOURCE_PROTOCOL_VERSION
        && batch.generate.iter().any(|item| item.shared.is_some())
    {
        return Err(DeploymentError::Invalid(
            "shared sources need deployment protocol 3",
        ));
    }
    for item in &batch.generate {
        if let Some(shared) = &item.shared {
            validate_identifier(&item.identifier)?;
            if available.iter().any(|secret| secret.identifier == item.identifier) {
                return Err(DeploymentError::Invalid(
                    "a shared source is a value of this target",
                ));
            }
            if shared.generator.is_empty()
                || shared.recipient_ids.is_empty()
                || shared.recipient_ids.len() != shared.recipient_public_keys.len()
            {
                return Err(DeploymentError::Invalid("invalid shared source"));
            }
            let contribution = Zeroizing::new(
                STANDARD
                    .decode(&item.client_contribution_base64)
                    .map_err(|_| DeploymentError::Invalid("invalid client contribution encoding"))?,
            );
            if contribution.len() != 32 {
                return Err(DeploymentError::Invalid(
                    "client contribution must be exactly 32 bytes",
                ));
            }
            continue;
        }
        if supplied.contains(&item.identifier) {
            return Err(DeploymentError::Invalid(
                "a value is both supplied and generated",
            ));
        }
        let target = available
            .iter()
            .find(|secret| secret.identifier == item.identifier)
            .ok_or(DeploymentError::Invalid(
                "generated identifier is absent from target schema",
            ))?;
        if target.generator.is_none() || target.public_info.is_some() {
            return Err(DeploymentError::Invalid(
                "target cannot generate this value",
            ));
        }
        let contribution = Zeroizing::new(
            STANDARD
                .decode(&item.client_contribution_base64)
                .map_err(|_| DeploymentError::Invalid("invalid client contribution encoding"))?,
        );
        if contribution.len() != 32 {
            return Err(DeploymentError::Invalid(
                "client contribution must be exactly 32 bytes",
            ));
        }
    }
    let generated = batch
        .generate
        .iter()
        .map(|item| item.identifier.as_str())
        .collect::<BTreeSet<_>>();
    for identifier in &batch.derive {
        if supplied.contains(identifier) || generated.contains(identifier.as_str()) {
            return Err(DeploymentError::Invalid(
                "a derived value is also supplied or generated",
            ));
        }
        let source = available
            .iter()
            .find(|secret| &secret.identifier == identifier)
            .and_then(|secret| secret.derived.as_deref())
            .and_then(|derived| serde_json::from_str::<serde_json::Value>(derived).ok())
            .and_then(|derived| derived["identifier"].as_str().map(str::to_owned))
            .ok_or(DeploymentError::Invalid(
                "target declares no derivation for a derived value",
            ))?;
        if !generated.contains(source.as_str()) {
            return Err(DeploymentError::Invalid(
                "a target-derived value needs its source generated in the same batch",
            ));
        }
    }
    validate_supplied(
        &batch.requested_identifiers,
        entries
            .iter()
            .map(|item| &item.identifier)
            .chain(
                batch
                    .generate
                    .iter()
                    .filter(|item| item.shared.is_none())
                    .map(|item| &item.identifier),
            )
            .chain(batch.derive.iter()),
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

/// Checks that the target would generate each requested value exactly as the
/// operator's schema describes it.
pub(super) fn verify_generators(
    state: &TargetState,
    expected: &ExpectedTarget,
    identifiers: &[String],
) -> Result<(), DeploymentError> {
    for identifier in identifiers {
        let want = expected
            .secrets
            .iter()
            .find(|item| &item.identifier == identifier)
            .and_then(|item| item.generator.as_ref())
            .ok_or(DeploymentError::Invalid(
                "operator schema cannot generate a requested value",
            ))?;
        let have = state
            .secrets
            .iter()
            .find(|item| &item.identifier == identifier)
            .and_then(|item| item.generator.as_ref())
            .ok_or(DeploymentError::Invalid(
                "target cannot generate a requested value; rebuild it with this schema",
            ))?;
        if want != have {
            return Err(DeploymentError::Invalid(
                "target would generate a value in another format; rebuild it with this schema",
            ));
        }
    }
    Ok(())
}

/// `right` names only identifiers of `left`, each once.
pub(super) fn require_subset(
    left: &[String],
    right: &[String],
    message: &'static str,
) -> Result<(), DeploymentError> {
    let left = left.iter().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    if right.iter().all(|item| left.contains(item) && seen.insert(item)) {
        Ok(())
    } else {
        Err(DeploymentError::Invalid(message))
    }
}
