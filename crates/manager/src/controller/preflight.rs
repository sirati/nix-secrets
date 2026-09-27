//! What a deployment can do, decided from the evaluated schema and the store
//! before any host-key scan, SSH connection or 1Password prompt.
//!
//! The backend holds the target host's whole evaluated configuration, so
//! the target must never be surprised by something the backend could have
//! predicted. Each check either leaves a value out, listed under "Cannot
//! deploy" with its precise reason, or refuses the whole deployment before
//! connecting. The target still checks everything again.

use super::unset::{MissingKind, UnsetPlan};
use super::*;
use nix_secrets_core::schema::SecretNode;
use nix_secrets_transport::{GENERATION_PROTOCOL_VERSION, NOT_DEPLOYED_PROTOCOL_VERSION};

/// Refuses the whole deployment, before connecting, when the host's
/// configuration cannot deploy at all: no forwarder key or no recipients.
pub(crate) fn refusal(schema: &Schema, target: &str) -> Option<String> {
    let host = schema.0.get(target)?;
    if host.metadata.deployment.identity_public_keys.is_empty() {
        return None;
    }
    let invalid = host
        .metadata
        .deployment
        .identity_public_keys
        .iter()
        .filter(|key| ssh_key::PublicKey::from_openssh(key).is_err())
        .collect::<Vec<_>>();
    (!invalid.is_empty()).then(|| {
        format!(
            "{target}: cannot deploy: its forwarder key is not an OpenSSH public key: {}",
            invalid
                .iter()
                .map(|key| key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

/// Leaves out every value of `identifiers` the host cannot receive, with the
/// precise reason. `set` names values with a stored (or default) value, as
/// for [`super::unset::plan_unset`].
pub(crate) fn check(
    schema: &Schema,
    identifiers: &[String],
    set: &BTreeSet<String>,
    plan: &mut UnsetPlan,
) {
    let Some(target) = identifiers
        .first()
        .and_then(|identifier| identifier.split('.').next())
    else {
        return;
    };
    let Some(host) = schema.0.get(target) else {
        return;
    };
    let protocol = host.metadata.deployment.protocol_version;
    let already = |plan: &UnsetPlan, identifier: &str| {
        plan.missing.iter().any(|(id, _)| id == identifier)
    };
    for identifier in identifiers {
        if already(plan, identifier) {
            continue;
        }
        let Ok(path) = SecretPath::parse(identifier) else {
            continue;
        };
        let Ok(leaf) = schema.leaf(&path) else {
            continue;
        };
        let reason = match &leaf {
            LeafSpec::Generated(task) => task_problem(host, identifiers, set, task),
            LeafSpec::Stored(spec) => stored_problem(spec, plan, identifier, protocol),
            LeafSpec::Operator(_) => None,
        };
        if let Some(reason) = reason {
            plan.miss(identifier, MissingKind::CannotDeploy, reason);
        }
    }
    // A derived value framed on the target from a source it can no longer
    // generate waits with its source.
    let left_out = plan
        .missing
        .iter()
        .map(|(identifier, _)| identifier.clone())
        .collect::<BTreeSet<_>>();
    plan.generate
        .retain(|(identifier, _)| !left_out.contains(identifier));
    let waiting = plan
        .derived_on_target
        .iter()
        .filter(|(_, source)| {
            !plan.generate.iter().chain(&plan.shared).any(|(id, _)| id == source)
        })
        .cloned()
        .collect::<Vec<_>>();
    for (identifier, source) in waiting {
        plan.derived_on_target.retain(|(id, _)| id != &identifier);
        if !already(plan, &identifier) {
            plan.miss(
                &identifier,
                MissingKind::CannotDeploy,
                format!("its source {source} cannot be generated in this deployment"),
            );
        }
    }
}

/// Why a stored value cannot be deployed to a receiver of `protocol`.
fn stored_problem(
    spec: &nix_secrets_core::SecretSpec,
    plan: &UnsetPlan,
    identifier: &str,
    protocol: Option<u16>,
) -> Option<String> {
    let protocol = protocol?;
    let needs = |version: u16, feature: &str| {
        (protocol < version).then(|| {
            format!("the host's receiver speaks deployment protocol {protocol}, and {feature} needs {version}; update the host first")
        })
    };
    let generated = plan.generate.iter().any(|(id, _)| id == identifier);
    let derived_on_target = plan.derived_on_target.iter().any(|(id, _)| id == identifier);
    if generated || derived_on_target {
        if let Some(reason) = needs(GENERATION_PROTOCOL_VERSION, "generating a value on the target") {
            return Some(reason);
        }
    }
    let shared_source = plan
        .derived_on_target
        .iter()
        .find(|(id, _)| id == identifier)
        .is_some_and(|(_, source)| plan.shared.iter().any(|(id, _)| id == source));
    if shared_source {
        if let Some(reason) = needs(
            nix_secrets_transport::SHARED_SOURCE_PROTOCOL_VERSION,
            "generating another host's shared secret",
        ) {
            return Some(reason);
        }
    }
    if spec
        .derived_from
        .as_ref()
        .is_some_and(|derived| !derived.toml_path.is_empty())
    {
        if let Some(reason) = needs(
            nix_secrets_transport::SHARED_SOURCE_PROTOCOL_VERSION,
            "derivedFrom.tomlPath",
        ) {
            return Some(reason);
        }
    }
    if matches!(spec.kind, SecretKind::PublicInfo)
        && (spec.ssh_hosts().len() > 1 || multi_line(spec))
    {
        return needs(
            NOT_DEPLOYED_PROTOCOL_VERSION,
            "public information with several hosts or key lines",
        );
    }
    None
}

fn multi_line(spec: &nix_secrets_core::SecretSpec) -> bool {
    spec.default_value
        .as_deref()
        .is_some_and(|value| value.trim_end_matches('\n').contains('\n'))
}

/// Why a target task cannot run: its bootstrap's known_hosts file is not
/// public information this deployment or the host's configuration provides.
fn task_problem(
    host: &nix_secrets_core::schema::HostSchema,
    identifiers: &[String],
    set: &BTreeSet<String>,
    task: &nix_secrets_core::GeneratedSecretSpec,
) -> Option<String> {
    let bootstrap = task.generated_secret.bootstrap.as_ref()?;
    let file = bootstrap.known_hosts_file.as_deref()?;
    let hostname = task.path.components().first()?.clone();
    let Some((identifier, leaf)) = attesting_leaf(host, &hostname, file, &bootstrap.host, bootstrap.port)
    else {
        return Some(format!(
            "its knownHostsFile {file} is not public information of {hostname} for [{}]:{}; declare it with expectedSshHost or expectedSshHosts",
            bootstrap.host, bootstrap.port
        ));
    };
    let value = leaf.default_value.as_deref();
    let provided = set.contains(&identifier) && identifiers.contains(&identifier);
    let installed_by_host = leaf.install_default_if_missing && value.is_some();
    if !provided && !installed_by_host {
        return Some(format!(
            "{file} is absent: {identifier} has no stored value and no defaultValue; enter it, or set defaultValue in the host's configuration"
        ));
    }
    // A stored record overrides the default, and was checked when it was
    // entered; the target checks whatever arrives again.
    if let Some(value) = value {
        let hosts = leaf.ssh_hosts();
        match nix_secrets_core::schema::known_hosts_keys(value, &hosts, bootstrap.port, &bootstrap.host) {
            Ok(keys) if keys.is_empty() => {
                return Some(format!(
                    "the default of {identifier} holds no key for [{}]:{}",
                    bootstrap.host, bootstrap.port
                ))
            }
            Err(error) => return Some(format!("the default of {identifier} is invalid: {error}")),
            Ok(_) => {}
        }
    }
    None
}

/// The public-info leaf of `host` whose destination is `file` and which
/// attests `server` on `port`, with its identifier.
fn attesting_leaf(
    host: &nix_secrets_core::schema::HostSchema,
    hostname: &str,
    file: &str,
    server: &str,
    port: u16,
) -> Option<(String, nix_secrets_core::schema::SecretLeaf)> {
    fn walk(
        prefix: String,
        node: &SecretNode,
        file: &str,
        server: &str,
        port: u16,
    ) -> Option<(String, nix_secrets_core::schema::SecretLeaf)> {
        match node {
            SecretNode::Secret(leaf)
                if matches!(leaf.kind, SecretKind::PublicInfo)
                    && leaf.destination.path == file
                    && leaf.ssh_hosts().contains(&server)
                    && leaf.expected_ssh_port == Some(port) =>
            {
                Some((prefix, leaf.clone()))
            }
            SecretNode::Branch(children) => children
                .iter()
                .find_map(|(name, child)| walk(format!("{prefix}.{name}"), child, file, server, port)),
            _ => None,
        }
    }
    host.service_groups.iter().find_map(|(namespace, services)| {
        services.iter().find_map(|(service, node)| {
            walk(format!("{hostname}.{namespace}.{service}"), node, file, server, port)
        })
    })
}

#[cfg(test)]
mod tests;
