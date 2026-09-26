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
                return Err(format!("approval lease was lost: {error}"));
            }
            self.active
                .as_mut()
                .expect("approval remains active")
                .renewed_at = Instant::now();
            return Ok(None);
        }
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
        let set = self.plan_set(&request.secrets)?;
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
        let connection = Connection {
            destination: host.metadata.deployment.destination.clone(),
            host: host.metadata.deployment.host.clone(),
            port: host.metadata.deployment.port,
            known_hosts: self.known_hosts.clone(),
        };
        let expected = match expected_target(&self.schema, &request) {
            Ok(expected) => expected,
            Err(error) => {
                self.client
                    .resolve(request.id, lease_id, false, Some(error.clone()))
                    .map_err(|e| e.to_string())?;
                return Err(error);
            }
        };
        let host_key = match deployment::preflight(&connection) {
            Ok(preflight) => preflight,
            Err(error) => {
                self.client
                    .resolve(request.id, lease_id, false, Some(error.clone()))
                    .map_err(|e| e.to_string())?;
                return Err(error);
            }
        };
        let known = host_key.status == HostKeyStatus::Known;
        details.host_key = deployment::unknown_description(&host_key);
        self.active = Some(ActiveApproval {
            request,
            lease_id,
            connection,
            expected,
            identity: host_key.identity,
            prepared: None,
            target_approved: known,
            last_error: None,
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
            let active = self.active.as_ref().expect("active approval exists");
            details = self.approval_details(
                &active.request,
                active.prepared.as_ref().map(PreparedDeployment::state),
                &set,
            )?;
        }
        Ok(Some(details))
    }

    pub(super) fn approval_inner(
        &mut self,
        accepted: bool,
        allow_partial: bool,
    ) -> Result<Option<UiApproval>, String> {
        let result = self.answer_approval(accepted, allow_partial);
        if let (Err(error), Some(active)) = (&result, self.active.as_mut()) {
            // Reported to the requester if the operator then rejects.
            active.last_error = Some(error.clone());
        }
        result
    }

    fn answer_approval(
        &mut self,
        accepted: bool,
        allow_partial: bool,
    ) -> Result<Option<UiApproval>, String> {
        if accepted {
            if !self
                .active
                .as_ref()
                .ok_or("no claimed approval request")?
                .target_approved
            {
                self.prepare_active()?;
                let active = self.active.as_mut().expect("active approval exists");
                active.target_approved = true;
                let request = active.request.clone();
                let state = active
                    .prepared
                    .as_ref()
                    .map(PreparedDeployment::state)
                    .cloned();
                let set = self.plan_set(&request.secrets)?;
                return self
                    .approval_details(&request, state.as_ref(), &set)
                    .map(Some);
            }
            // The dialog shows the requester's choice and the operator may
            // change it; what they approved is what is deployed.
            let active = self.active.as_mut().expect("active approval exists");
            active.request.allow_partial = allow_partial;
            let (id, lease_id) = (active.request.id.clone(), active.lease_id);
            if let Err(error) = self.client.renew_for(id, lease_id, 900_000) {
                self.active.take();
                return Err(format!("approval lease was lost: {error}"));
            }
            self.active
                .as_mut()
                .expect("approval remains active")
                .renewed_at = Instant::now();
            self.deploy_active()?;
            return Ok(None);
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
