use crate::client::BackendClient;
use crate::deployment::{self, Connection};
use crate::model::ApprovalRequest as UiApproval;
use crate::tree::Row;
use crate::ui::{Action, SecretWriter};
use base64::{engine::general_purpose::STANDARD, Engine};
use nix_secrets_core::{ApprovalRequest, Schema, SecretPath};
use nix_secrets_crypto::{decrypt_secret, AgeCommandProvider, EncryptedSecret, Recipient};
use nix_secrets_transport::{
    DeployEntry, Destination, ExpectedSecret, ExpectedTarget, HostIdentity, HostKeyStatus,
    PreparedDeployment, TargetState,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

struct ActiveApproval {
    request: ApprovalRequest,
    lease_id: u64,
    connection: Connection,
    expected: ExpectedTarget,
    identity: HostIdentity,
    prepared: Option<PreparedDeployment>,
    target_approved: bool,
    renewed_at: Instant,
}

pub struct Controller {
    client: BackendClient,
    schema: Schema,
    provider: AgeCommandProvider,
    known_hosts: Vec<PathBuf>,
    active: Option<ActiveApproval>,
}

impl Controller {
    pub fn new(
        mut client: BackendClient,
        schema: Schema,
        provider: AgeCommandProvider,
        known_hosts: Vec<PathBuf>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        client.register_frontend()?;
        Ok(Self {
            client,
            schema,
            provider,
            known_hosts,
            active: None,
        })
    }

    pub fn rows(&mut self) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
        let set = self.client.list()?.into_keys().collect::<BTreeSet<_>>();
        Ok(crate::tree::rows(&self.schema, &set))
    }

    fn approval_details(
        &self,
        request: &ApprovalRequest,
        state: Option<&TargetState>,
    ) -> Result<UiApproval, String> {
        let mut create = Vec::new();
        let mut replace = Vec::new();
        let mut keys = BTreeSet::new();
        for identifier in &request.secrets {
            let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
            if path.components().first().map(String::as_str) != Some(request.target.as_str()) {
                return Err(format!(
                    "{identifier} does not belong to target {}",
                    request.target
                ));
            }
            let spec = self
                .schema
                .secret(&path)
                .map_err(|error| error.to_string())?;
            keys.extend(spec.recipient_ids);
            if let Some(state) = state {
                if target_has_version(state, identifier)? {
                    replace.push(identifier.clone());
                } else {
                    create.push(identifier.clone());
                }
            }
        }
        Ok(UiApproval {
            id: request.id.clone(),
            target: request.target.clone(),
            create,
            replace,
            recipient_keys: keys.into_iter().collect(),
            host_key: None,
        })
    }

    fn deploy_active(&mut self) -> Result<(), String> {
        if self
            .active
            .as_ref()
            .ok_or("no claimed approval request")?
            .prepared
            .is_none()
        {
            self.prepare_active()?;
        }
        let active = self.active.as_ref().expect("active approval exists");
        let entries = self.client.list().map_err(|error| error.to_string())?;
        let identifiers = active.request.secrets.clone();
        let deploy_entries = identifiers
            .iter()
            .map(|identifier| {
                let stored = entries
                    .get(identifier)
                    .ok_or_else(|| format!("required secret is unset: {identifier}"))?;
                let record = EncryptedSecret {
                    format_version: stored.format_version,
                    version_id: stored.version_id.clone(),
                    recipient_ids: stored.recipient_ids.clone(),
                    age_ciphertext: stored.age_ciphertext.clone(),
                };
                let value = decrypt_secret(identifier, &record, &self.provider)
                    .map_err(|error| error.to_string())?;
                Ok(DeployEntry {
                    identifier: identifier.clone(),
                    version_id: STANDARD.encode(&stored.version_id),
                    contents_base64: STANDARD.encode(&value),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let prepared = self
            .active
            .as_mut()
            .expect("active approval exists")
            .prepared
            .take()
            .expect("prepared above");
        deployment::deploy(prepared, deploy_entries)?;
        let active = self.active.take().expect("approval remains active");
        self.client
            .resolve(active.request.id, active.lease_id, true)
            .map_err(|error| error.to_string())
    }

    fn prepare_active(&mut self) -> Result<(), String> {
        let active = self.active.as_ref().ok_or("no claimed approval request")?;
        let prepared = deployment::prepare(&active.connection, &active.expected, &active.identity)?;
        self.active
            .as_mut()
            .expect("active approval exists")
            .prepared = Some(prepared);
        Ok(())
    }
}

mod writer;

fn expected_target(schema: &Schema, request: &ApprovalRequest) -> Result<ExpectedTarget, String> {
    let secrets = request
        .secrets
        .iter()
        .map(|identifier| {
            let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
            let spec = schema.secret(&path).map_err(|error| error.to_string())?;
            Ok(ExpectedSecret {
                identifier: identifier.clone(),
                recipient_ids: spec.recipient_ids,
                destination: Destination {
                    path: spec.destination.path,
                    category: spec.destination.category,
                    owner: spec.destination.owner,
                    group: spec.destination.group,
                    mode: spec.destination.mode,
                    consumer_units: spec.consumer_units,
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ExpectedTarget {
        hostname: request.target.clone(),
        secrets,
    })
}

fn target_has_version(state: &TargetState, identifier: &str) -> Result<bool, String> {
    state
        .secrets
        .iter()
        .find(|secret| secret.identifier == identifier)
        .map(|secret| secret.current_version_id.is_some())
        .ok_or_else(|| format!("target omitted {identifier}"))
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
            current_version_id: version.map(str::to_owned),
        };
        let state = TargetState {
            protocol_version: 1,
            hostname: "host".into(),
            secrets: vec![
                secret("host.services.s.new", None),
                secret("host.services.s.old", Some("version")),
            ],
        };
        assert!(!target_has_version(&state, "host.services.s.new").unwrap());
        assert!(target_has_version(&state, "host.services.s.old").unwrap());
    }
}
