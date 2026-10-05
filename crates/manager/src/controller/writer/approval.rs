use super::*;
impl Controller {
    pub(super) fn poll_approval_inner(&mut self) -> Result<Option<UiApproval>, String> {
        self.drain_background();
        if let Some(active) = &self.active {
            if active.renewed_at.elapsed() < Duration::from_secs(60) {
                return Ok(None);
            }
            let id = active.request.id.clone();
            let lease_id = active.lease_id;
            if let Err(error) = self.client.renew(id, lease_id) {
                self.active.take();
                self.host_mutations = None;
                self.identity_publication = None;
                return Err(format!("approval lease was lost: {error}"));
            }
            self.active
                .as_mut()
                .expect("approval remains active")
                .renewed_at = Instant::now();
            return Ok(None);
        }
        self.host_mutations = None;
        self.identity_publication = None;
        self.connection_warnings.clear();
        if self.background.is_some() && !std::mem::take(&mut self.approvals_ready) {
            return Ok(None);
        }
        let Some((request, lease_id)) = self
            .client
            .poll_and_claim()
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let set = self.plan_set(&request.secrets);
        let set = self.finish_claimed_setup(&request, lease_id, set)?;
        let mut details = match self.approval_details(&request, None, &set) {
            Ok(details) => details,
            Err(error) => {
                self.client
                    .resolve(request.id, lease_id, false, Some(error.clone()))
                    .map_err(|resolve| resolve.to_string())?;
                return Err(error);
            }
        };
        let host = match self.schema.0.get(&request.target) {
            Some(host) => host,
            None => {
                self.client
                    .resolve(
                        request.id,
                        lease_id,
                        false,
                        Some("target host is absent from schema".into()),
                    )
                    .map_err(|e| e.to_string())?;
                return Err("target host is absent from schema".into());
            }
        };
        // Refused from the host's configuration alone, before connecting.
        if let Some(error) = super::super::preflight::refusal(&self.schema, &request.target) {
            self.client
                .resolve(request.id, lease_id, false, Some(error.clone()))
                .map_err(|e| e.to_string())?;
            return Err(error);
        }
        let connection = Connection {
            name: request.target.clone(),
            identity_public_keys: host.metadata.deployment.identity_public_keys.clone(),
            destination: host.metadata.deployment.destination.clone(),
            host: host.metadata.deployment.host.clone(),
            port: host.metadata.deployment.port,
            known_hosts: self.known_hosts.clone(),
            backend_route: self.backend_route.clone(),
        };
        // The one connection selects only what can be deployed: values that
        // wait for another host are left out, so a partial deployment needs
        // no second connection, and a full one is refused before sending.
        // Unset public information with a host default is never sent either:
        // the host keeps the default it installs.
        let skippable = unset::plan_unset(&self.schema, &request.secrets, &set)
            .map(|plan| {
                plan.skippable
                    .into_iter()
                    .chain(plan.host_default)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut selected = request.clone();
        let producer_identity = self.producer_identity_in_scope(&request);
        selected.secrets.retain(|identifier| {
            !skippable.contains(identifier)
                || producer_identity.as_deref() == Some(identifier.as_str())
        });
        let expected = match expected_target(&self.schema, &selected) {
            Ok(expected) => expected,
            Err(error) => {
                self.client
                    .resolve(request.id, lease_id, false, Some(error.clone()))
                    .map_err(|e| e.to_string())?;
                return Err(error);
            }
        };
        // Nothing can be deployed: show why without scanning or connecting.
        if selected.secrets.is_empty() {
            self.active = Some(ActiveApproval {
                request,
                lease_id,
                connection,
                expected,
                identity: HostIdentity {
                    host: String::new(),
                    port: 0,
                    keys: vec![],
                    other_names_with_keys: vec![],
                },
                prepared: None,
                target_approved: true,
                last_error: None,
                unchecked: BTreeSet::new(),
                renewed_at: Instant::now(),
            });
            return Ok(Some(details));
        }
        let host_key = match deployment::preflight(&connection) {
            Ok(preflight) => preflight,
            Err(error) => {
                self.client
                    .resolve(request.id, lease_id, false, Some(error.clone()))
                    .map_err(|e| e.to_string())?;
                return Err(error);
            }
        };
        self.connection_warnings = host_key.connection_warnings.clone();
        let known = host_key.status == HostKeyStatus::Known;
        details.host_key = deployment::unknown_description(&connection, &host_key);
        self.active = Some(ActiveApproval {
            request,
            lease_id,
            connection,
            expected,
            identity: host_key.identity,
            prepared: None,
            target_approved: known,
            last_error: None,
            unchecked: BTreeSet::new(),
            renewed_at: Instant::now(),
        });
        if known {
            if let Err(error) = self.prepare_active() {
                let active = self.active.take().expect("active approval exists");
                self.client
                    .resolve(
                        active.request.id,
                        active.lease_id,
                        false,
                        Some(error.clone()),
                    )
                    .map_err(|resolve| resolve.to_string())?;
                return Err(error);
            }
            let request = self
                .active
                .as_ref()
                .expect("active approval exists")
                .request
                .clone();
            let refreshed = self.prepare_identity_for_active();
            details = self.finish_claimed_setup(&request, lease_id, refreshed)?;
        }
        Ok(Some(details))
    }

    /// Initial poll failures must end their broker claim, even before there is
    /// an active dialog. Drop any prepared connection and reject with the exact
    /// failure; never leave the operator renewing a request that cannot appear.
    fn finish_claimed_setup<T>(
        &mut self,
        request: &ApprovalRequest,
        lease_id: u64,
        result: Result<T, String>,
    ) -> Result<T, String> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                if self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.request.id == request.id)
                {
                    self.active.take();
                    self.host_mutations = None;
                    self.identity_publication = None;
                }
                self.client
                    .resolve(request.id.clone(), lease_id, false, Some(error.clone()))
                    .map_err(|resolve| {
                        format!("{error}; could not resolve failed approval setup: {resolve}")
                    })?;
                Err(error)
            }
        }
    }

    pub(super) fn approval_inner(&mut self, accepted: bool) -> Result<Option<UiApproval>, String> {
        let result = self.answer_approval(accepted);
        // A failure is final: the request is resolved with its reason and
        // never offered again. Retrying would open another authenticated
        // connection, and with it another agent or 1Password prompt.
        if let Err(error) = &result {
            self.host_mutations = None;
            self.identity_publication = None;
            if let Some(active) = self.active.take() {
                let _ = self.client.resolve(
                    active.request.id,
                    active.lease_id,
                    false,
                    Some(error.clone()),
                );
            }
        }
        result
    }

    fn answer_approval(&mut self, accepted: bool) -> Result<Option<UiApproval>, String> {
        if self.host_mutations.is_some() {
            return Err("host-provided changes require their displayed review token".into());
        }
        if accepted {
            if !self
                .active
                .as_ref()
                .ok_or("no claimed approval request")?
                .target_approved
            {
                let active = self.active.as_ref().expect("active approval exists");
                let verifier =
                    nix_secrets_transport::HostKeyVerifier::new(self.known_hosts.clone())
                        .with_route(self.backend_route.clone());
                verifier
                    .preflight_approved(
                        &active.connection.host,
                        active.connection.port,
                        &active.identity,
                    )
                    .map_err(|e| e.to_string())?;
                verifier
                    .persist_accepted(&active.identity)
                    .map_err(|e| e.to_string())?;
                self.prepare_active()?;
                let active = self.active.as_mut().expect("active approval exists");
                active.target_approved = true;
                return self.prepare_identity_for_active().map(Some);
            }
            let active = self.active.as_mut().expect("active approval exists");
            let (id, lease_id) = (active.request.id.clone(), active.lease_id);
            if let Err(error) = self.client.renew_for(id, lease_id, 900_000) {
                self.active.take();
                self.host_mutations = None;
                self.identity_publication = None;
                return Err(format!("approval lease was lost: {error}"));
            }
            self.active
                .as_mut()
                .expect("approval remains active")
                .renewed_at = Instant::now();
            return self.deploy_active();
        }
        let active = self.active.take().ok_or("no claimed approval request")?;
        let reason = match active.last_error {
            Some(error) => format!("rejected by the operator after: {error}"),
            None => "rejected by the operator".to_owned(),
        };
        self.client
            .resolve(active.request.id, active.lease_id, false, Some(reason))
            .map_err(|error| error.to_string())?;
        Ok(None)
    }
}

#[cfg(test)]
#[path = "approval_setup_tests.rs"]
mod tests;
