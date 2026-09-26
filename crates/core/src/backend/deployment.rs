//! Operator-initiated deployments: `nix-secrets deploy HOST` asks the
//! registered frontends to deploy every deployable value of a host through
//! the ordinary approval flow.
use super::{Response, Schema};
use crate::approval::{ApprovalBroker, BrokerError};
use crate::approval_types::ApprovalRequest;
use std::sync::Mutex;

/// Builds the approval request for `target` and queues it. The request
/// covers the whole manifest of the host, so the frontend classifies every
/// value: stored, generated on the target, derived, public information and
/// target tasks.
pub(super) fn request(
    schema: &Schema,
    broker: &Mutex<ApprovalBroker>,
    target: String,
    allow_partial: bool,
) -> Result<Response, String> {
    let secrets = schema
        .deployable_identifiers(&target)
        .map_err(|_| format!("{target} is not a host of the evaluated schema"))?;
    if secrets.is_empty() {
        return Err(format!("{target} declares no deployable values"));
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    let request = ApprovalRequest {
        id: format!(
            "deploy-{}",
            random.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
        ),
        target,
        secrets,
        allow_partial,
    };
    let mut state = broker
        .lock()
        .map_err(|_| "approval broker lock is poisoned".to_owned())?;
    // A request nobody can answer would only wait for its lease forever.
    if !state.has_frontends() {
        return Err(super::NO_OPERATOR.to_owned());
    }
    state.submit(request.clone()).map_err(|error| match error {
        BrokerError::Invalid(message) => message.to_owned(),
        BrokerError::Full => "approval broker capacity reached".to_owned(),
        _ => "the deployment request could not be queued".to_owned(),
    })?;
    Ok(Response::DeploymentRequested { request })
}
