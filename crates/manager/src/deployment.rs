use nix_secrets_transport::{
    Decision, DeployEntry, DeploymentResult, ExpectedTarget, HostIdentity, HostKeyPreflight,
    HostKeyStatus, HostKeyVerifier, OpenSsh, PreparedDeployment, TaskEntry,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Connection {
    pub destination: String,
    pub host: String,
    pub port: u16,
    pub known_hosts: Vec<PathBuf>,
}

pub fn preflight(connection: &Connection) -> Result<HostKeyPreflight, String> {
    HostKeyVerifier::new(connection.known_hosts.clone())
        .preflight(&connection.host, connection.port)
        .map_err(|error| error.to_string())
}

pub fn unknown_description(preflight: &HostKeyPreflight) -> Option<String> {
    if preflight.status != HostKeyStatus::Unknown {
        return None;
    }
    let keys = preflight
        .identity
        .keys
        .iter()
        .map(|key| format!("{} {}", key.algorithm, key.encoded))
        .collect::<Vec<_>>()
        .join(", ");
    let aliases = preflight.identity.other_names_with_keys.join(", ");
    Some(format!(
        "UNKNOWN SSH HOST KEY: {keys}; known names with this key: [{aliases}]."
    ))
}

pub fn prepare(
    connection: &Connection,
    expected: &ExpectedTarget,
    approved_identity: &HostIdentity,
) -> Result<PreparedDeployment, String> {
    let open = OpenSsh {
        program: OsString::from("ssh"),
        destination: OsString::from(&connection.destination),
        host: connection.host.clone(),
        port: connection.port,
        verifier: HostKeyVerifier::new(connection.known_hosts.clone()),
    };
    let current = open
        .verifier
        .preflight(&connection.host, connection.port)
        .map_err(|error| error.to_string())?;
    if &current.identity != approved_identity {
        return Err("SSH host identity changed since approval".into());
    }
    let decision = if current.status == HostKeyStatus::Unknown {
        Decision::Accept
    } else {
        Decision::Reject
    };
    let session = open
        .connect_preflight(current, decision)
        .map_err(|error| error.to_string())?;
    PreparedDeployment::open(session, expected).map_err(|error| error.to_string())
}

pub fn deploy(
    prepared: PreparedDeployment,
    entries: Vec<DeployEntry>,
    tasks: Vec<TaskEntry>,
) -> Result<BTreeMap<String, String>, String> {
    match prepared
        .deploy_with_tasks(entries, tasks)
        .map_err(|error| error.to_string())?
    {
        DeploymentResult::Applied {
            generated_public_keys,
            ..
        } => return Ok(generated_public_keys),
        DeploymentResult::Rejected { message } => {
            return Err(format!("target rejected deployment: {message}"))
        }
    }
}
