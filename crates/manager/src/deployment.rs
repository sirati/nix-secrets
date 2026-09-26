use nix_secrets_transport::{
    AppliedOutput, Decision, DeployEntry, DeploymentResult, ExpectedTarget, GenerateEntry,
    HostIdentity, HostKeyError, HostKeyPreflight, HostKeyStatus, HostKeyVerifier, Offer, OpenSsh,
    PreparedDeployment, TaskEntry,
};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Connection {
    /// The host's name in the schema, such as `ns1`.
    pub name: String,
    pub destination: String,
    pub host: String,
    pub port: u16,
    pub known_hosts: Vec<PathBuf>,
    /// The public keys the target's forwarder authorizes; the only ones
    /// offered. Empty: ssh's own choice.
    pub identity_public_keys: Vec<String>,
}

impl Connection {
    /// `nix-secrets-forward@ns1.lamk.eu:22`.
    pub fn target(&self) -> String {
        format!("{}:{}", self.destination, self.port)
    }

    /// The known_hosts files that exist, for messages.
    fn known_hosts_files(&self) -> String {
        let files = self
            .known_hosts
            .iter()
            .filter(|path| path.exists())
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        if files.is_empty() {
            "none of this machine's known_hosts files".into()
        } else {
            files.join(" and ")
        }
    }

    /// Chooses the key the deployment offers, from the client's ssh config
    /// and agent. Listing agent keys asks nothing of 1Password.
    pub fn identities(&self) -> Result<Vec<Offer>, String> {
        if self.identity_public_keys.is_empty() {
            return Ok(Vec::new());
        }
        let program = OsString::from("ssh");
        let config = nix_secrets_transport::client_config(
            &program,
            &OsString::from(&self.destination),
            self.port,
        );
        let agent = nix_secrets_transport::agent_keys(config.identity_agent.as_deref());
        nix_secrets_transport::choose(&self.identity_public_keys, &config, agent, &|path| {
            std::fs::read_to_string(path).ok()
        })
        .map_err(|error| format!("Cannot deploy {} ({}): {error}", self.name, self.target()))
    }
}

/// A host-key failure, naming the host and what to do.
pub fn host_key_error(connection: &Connection, error: HostKeyError) -> String {
    let host = format!(
        "{} ({}:{})",
        connection.name, connection.host, connection.port
    );
    match error {
        HostKeyError::Changed(changed) => format!(
            "Cannot deploy {host}: {changed}\nThe known_hosts files checked: {}.",
            connection.known_hosts_files()
        ),
        HostKeyError::NoKeys => format!("Cannot deploy {host}: it presented no SSH host key."),
        HostKeyError::UnknownRejected => format!(
            "Cannot deploy {host}: its SSH host key is not in {} and was not trusted.",
            connection.known_hosts_files()
        ),
        HostKeyError::Tool(message) if message == "ssh-keyscan failed" => format!(
            "Cannot deploy {host}: ssh-keyscan could not read its host key; the host may be unreachable on port {}.",
            connection.port
        ),
        other => format!("Cannot deploy {host}: {other}"),
    }
}

pub fn preflight(connection: &Connection) -> Result<HostKeyPreflight, String> {
    HostKeyVerifier::new(connection.known_hosts.clone())
        .preflight(&connection.host, connection.port)
        .map_err(|error| host_key_error(connection, error))
}

pub fn unknown_description(
    connection: &Connection,
    preflight: &HostKeyPreflight,
) -> Option<String> {
    if preflight.status != HostKeyStatus::Unknown {
        return None;
    }
    let keys = preflight
        .identity
        .keys
        .iter()
        .map(|key| key.describe())
        .collect::<Vec<_>>()
        .join(", ");
    let aliases = if preflight.identity.other_names_with_keys.is_empty() {
        "no other name in known_hosts has these keys".to_owned()
    } else {
        format!(
            "known under other names: {}",
            preflight.identity.other_names_with_keys.join(", ")
        )
    };
    Some(format!(
        "UNKNOWN SSH HOST KEY for {} ({}:{}): {keys}; it is not in {} ({aliases}). Compare it with the host's own fingerprint (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on its console) before trusting it.",
        connection.name,
        connection.host,
        connection.port,
        connection.known_hosts_files()
    ))
}

/// Describes a scan whose keys differ from the approved ones.
fn identity_changed(
    connection: &Connection,
    approved: &HostIdentity,
    current: &HostIdentity,
) -> String {
    let list = |identity: &HostIdentity| {
        identity
            .keys
            .iter()
            .map(|key| key.describe())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "Cannot deploy {} ({}:{}): its SSH host keys changed after you approved them.\n  approved: {}\n  now:      {}\nNothing was sent. If the host was just reinstalled, compare the new fingerprint with the host's own and retry; otherwise someone may be intercepting the connection.",
        connection.name,
        connection.host,
        connection.port,
        list(approved),
        list(current)
    )
}

/// Opens the one authenticated connection of a deployment and reads the
/// target's state over it.
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
        identities: connection.identities()?,
    };
    let current = open
        .verifier
        .preflight(&connection.host, connection.port)
        .map_err(|error| host_key_error(connection, error))?;
    if &current.identity != approved_identity {
        return Err(identity_changed(
            connection,
            approved_identity,
            &current.identity,
        ));
    }
    let decision = if current.status == HostKeyStatus::Unknown {
        Decision::Accept
    } else {
        Decision::Reject
    };
    let session = open
        .connect_preflight(current, decision)
        .map_err(|error| format!("Cannot deploy {}: {error}", connection.name))?;
    PreparedDeployment::open(session, expected)
        .map_err(|error| format!("Cannot deploy {}: {error}", connection.name))
}
pub fn deploy(
    prepared: PreparedDeployment,
    entries: Vec<DeployEntry>,
    tasks: Vec<TaskEntry>,
    generate: Vec<GenerateEntry>,
    derive: Vec<String>,
) -> Result<AppliedOutput, String> {
    let requested = generate
        .iter()
        .map(|item| item.identifier.clone())
        .collect::<std::collections::BTreeSet<_>>();
    match prepared
        .deploy_with_generation(entries, tasks, generate, derive)
        .map_err(|error| error.to_string())?
    {
        DeploymentResult::Applied {
            versions,
            generated_public_keys,
            generated_records,
        } => {
            if generated_records
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                != requested
            {
                return Err("target returned records for other values than requested".into());
            }
            Ok(AppliedOutput {
                versions,
                generated_public_keys,
                generated_records,
            })
        }
        DeploymentResult::Rejected { message } => {
            Err(format!("target rejected deployment: {message}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_secrets_transport::{ChangedHostKey, KnownKey, PresentedKey};

    fn connection(known_hosts: PathBuf) -> Connection {
        Connection {
            name: "ns1".into(),
            destination: "nix-secrets-forward@ns1.lamk.eu".into(),
            host: "ns1.lamk.eu".into(),
            port: 22,
            known_hosts: vec![known_hosts],
            identity_public_keys: vec![],
        }
    }

    fn key(encoded: &str) -> PresentedKey {
        PresentedKey {
            algorithm: "ssh-ed25519".into(),
            encoded: encoded.into(),
        }
    }

    #[test]
    fn host_key_errors_name_the_host_the_keys_and_the_client_file() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("known_hosts");
        std::fs::write(&file, "").unwrap();
        let connection = connection(file.clone());
        let changed = host_key_error(
            &connection,
            HostKeyError::Changed(Box::new(ChangedHostKey {
                host: "ns1.lamk.eu".into(),
                port: 22,
                expected: vec![KnownKey {
                    file: file.clone(),
                    line: Some(4),
                    key: key("AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"),
                }],
                offered: vec![key("AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA")],
            })),
        );
        assert!(changed.starts_with("Cannot deploy ns1 (ns1.lamk.eu:22)"), "{changed}");
        assert!(changed.contains("SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA"), "{changed}");
        assert!(changed.contains("line 4"), "{changed}");
        assert!(changed.contains(&format!("ssh-keygen -R ns1.lamk.eu -f {}", file.display())), "{changed}");
        assert!(changed.contains(&format!("The known_hosts files checked: {}", file.display())), "{changed}");
        let rejected = host_key_error(&connection, HostKeyError::UnknownRejected);
        assert!(rejected.contains("ns1 (ns1.lamk.eu:22)") && rejected.contains(&file.display().to_string()), "{rejected}");
        let approved = HostIdentity {
            host: "ns1.lamk.eu".into(),
            port: 22,
            keys: vec![key("AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f")],
            other_names_with_keys: vec![],
        };
        let mut now = approved.clone();
        now.keys = vec![key("AAAAC3NzaC1lZDI1NTE5AAAAIB8eHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgEA")];
        let text = identity_changed(&connection, &approved, &now);
        assert!(text.contains("ns1 (ns1.lamk.eu:22)") && text.contains("approved: ssh-ed25519 SHA256:ZkAsl"), "{text}");
        assert!(text.contains("Nothing was sent"), "{text}");
    }
}
