use super::*;
use nix_secrets_transport::PublicInfoAttestation;

pub(super) fn expected_target(
    schema: &Schema,
    request: &ApprovalRequest,
) -> Result<ExpectedTarget, String> {
    let mut secrets = Vec::new();
    let mut tasks = Vec::new();
    for identifier in &request.secrets {
        let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
        match schema.leaf(&path).map_err(|error| error.to_string())? {
            LeafSpec::Stored(spec) => secrets.push(ExpectedSecret {
                identifier: identifier.clone(),
                generator: super::unset::expected_generator(&spec),
                recipient_ids: spec.recipient_ids,
                destination: destination(spec.destination, spec.consumer_units),
                public_info: spec
                    .shared_public_id
                    .map(|shared_id| PublicInfoAttestation {
                        shared_id,
                        expected_ssh_host: spec.expected_ssh_host.unwrap_or_default(),
                        expected_ssh_port: spec.expected_ssh_port.unwrap_or_default(),
                    }),
            }),
            LeafSpec::Generated(spec) => tasks.push(ExpectedTask {
                identifier: identifier.clone(),
                task_type: match spec.generated_secret.secret_type {
                    nix_secrets_core::GeneratedSecretType::StorageBoxSshKey => STORAGE_BOX_SSH_KEY,
                    nix_secrets_core::GeneratedSecretType::LocalSshKey => {
                        nix_secrets_transport::LOCAL_SSH_KEY
                    }
                }
                .into(),
                recipient_ids: spec.recipient_ids,
                output: destination(spec.generated_secret.output, spec.consumer_units),
                bootstrap: spec
                    .generated_secret
                    .bootstrap
                    .map(|bootstrap| StorageBoxBootstrap {
                        host: bootstrap.host,
                        port: bootstrap.port,
                        user: bootstrap.user,
                        host_public_keys: bootstrap.host_public_keys,
                        known_hosts_file: bootstrap.known_hosts_file,
                    }),
            }),
        }
    }
    Ok(ExpectedTarget {
        hostname: request.target.clone(),
        secrets,
        tasks,
    })
}

pub(super) fn destination(
    value: nix_secrets_core::Destination,
    consumer_units: Vec<String>,
) -> Destination {
    Destination {
        path: value.path,
        category: value.category,
        owner: value.owner,
        group: value.group,
        mode: value.mode,
        consumer_units,
    }
}

pub(super) fn target_has_version(state: &TargetState, identifier: &str) -> Result<bool, String> {
    state
        .secrets
        .iter()
        .find(|secret| secret.identifier == identifier)
        .map(|secret| secret.current_version_id.is_some())
        .ok_or_else(|| format!("target omitted {identifier}"))
}

pub(super) fn target_task_has_version(
    state: &TargetState,
    identifier: &str,
) -> Result<bool, String> {
    state
        .tasks
        .iter()
        .find(|task| task.identifier == identifier)
        .map(|task| task.current_version_id.is_some())
        .ok_or_else(|| format!("target omitted task {identifier}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_secrets_transport::TargetSecret;

    #[test]
    fn target_state_is_authoritative_for_create_and_replace() {
        let destination = Destination {
            path: "/persistent/secrets/s/service/a".into(),
            category: "service".into(),
            owner: "s".into(),
            group: "s".into(),
            mode: "0400".into(),
            consumer_units: vec![],
        };
        let secret = |identifier: &str, version: Option<&str>| TargetSecret {
            identifier: identifier.into(),
            recipient_ids: vec!["key".into()],
            destination: destination.clone(),
            public_info: None,
            current_version_id: version.map(str::to_owned),
            generator: None,
        };
        let state = TargetState {
            protocol_version: 1,
            hostname: "host".into(),
            secrets: vec![
                secret("host.services.s.new", None),
                secret("host.services.s.old", Some("version")),
            ],
            tasks: vec![],
        };
        assert!(!target_has_version(&state, "host.services.s.new").unwrap());
        assert!(target_has_version(&state, "host.services.s.old").unwrap());
    }
}
