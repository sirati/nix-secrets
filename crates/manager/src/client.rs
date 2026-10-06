mod commit;
mod profiles;
mod public_info;
mod subscription;
use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{
    ApprovalRequest, ApprovalStatus, BackendEvent, CommitState, Decision,
    EncryptedSecret as StoredSecret, GeneratedPublicKey, ProfileSnapshot, PublicInfoRecord,
    Request, Response, SecretPath, ViewProfile,
};
use nix_secrets_core::procedure::ProcedureStep;
use nix_secrets_crypto::{encrypt_secret, CryptoProvider, Recipient};
use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;

pub struct BackendClient {
    stream: UnixStream,
}

impl BackendClient {
    pub fn read_signing_artifact(
        &mut self,
        request_id: &str,
        role: &str,
        offset: u64,
    ) -> Result<Vec<u8>, String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        match self
            .exchange(&Request::ReadSigningArtifact {
                request_id: request_id.into(),
                role: role.into(),
                offset,
            })
            .map_err(|e| e.to_string())?
        {
            Response::SigningArtifactChunk {
                offset: received,
                bytes_base64,
            } if received == offset
                && bytes_base64.len()
                    <= 4 * nix_secrets_core::artifact_signing::CHUNK_BYTES.div_ceil(3) =>
            {
                let bytes = STANDARD
                    .decode(bytes_base64)
                    .map_err(|_| "invalid artifact chunk encoding")?;
                if bytes.is_empty() || bytes.len() > nix_secrets_core::artifact_signing::CHUNK_BYTES
                {
                    return Err("invalid artifact chunk size".into());
                }
                Ok(bytes)
            }
            Response::Error { message } => Err(message),
            _ => Err("unexpected signing artifact chunk".into()),
        }
    }
    pub fn new(stream: UnixStream) -> Self {
        Self { stream }
    }

    pub fn list(&mut self) -> io::Result<BTreeMap<String, StoredSecret>> {
        match self.exchange(&Request::List)? {
            Response::Secrets { entries } => Ok(entries),
            response => Err(unexpected(response)),
        }
    }

    pub fn commit_state(&mut self, path: &SecretPath) -> io::Result<CommitState> {
        match self.exchange(&Request::CommitState { path: path.clone() })? {
            Response::CommitState { state } => Ok(state),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn get(&mut self, path: &SecretPath) -> io::Result<Option<StoredSecret>> {
        match self.exchange(&Request::Get { path: path.clone() })? {
            Response::Secret { envelope } => Ok(envelope),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn generated_public_key(
        &mut self,
        path: &SecretPath,
    ) -> io::Result<Option<GeneratedPublicKey>> {
        match self.exchange(&Request::GetGeneratedPublicKey { path: path.clone() })? {
            Response::GeneratedPublicKey { value } => Ok(value),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn set_generated_public_key_if_version(
        &mut self,
        path: &SecretPath,
        value: GeneratedPublicKey,
        expected_version: Option<String>,
    ) -> io::Result<()> {
        match self.exchange(&Request::SetGeneratedPublicKeyIfVersion {
            path: path.clone(),
            value,
            expected_version,
        })? {
            Response::Updated => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn set_public_key_if_version(
        &mut self,
        path: &SecretPath,
        public_key: String,
        expected_version: Vec<u8>,
        expected_public_key: Option<String>,
    ) -> io::Result<()> {
        match self.exchange(&Request::SetPublicKeyIfVersion {
            path: path.clone(),
            public_key,
            expected_version,
            expected_public_key,
        })? {
            Response::Updated => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn set_private_key(
        &mut self,
        path: &SecretPath,
        plaintext: &[u8],
        recipients: &[Recipient<'_>],
        provider: &impl CryptoProvider,
        public_key: String,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let expected_version = self.get(path)?.map(|record| record.version_id);
        let encrypted = encrypt_secret(&path.to_string(), plaintext, recipients, provider)?;
        let version = encrypted.version_id.clone();
        let envelope = StoredSecret {
            format_version: encrypted.format_version,
            version_id: encrypted.version_id,
            recipient_ids: encrypted.recipient_ids,
            recipient_refs: vec![],
            age_ciphertext: encrypted.age_ciphertext,
            public_key: Some(public_key),
        };
        match self.exchange(&Request::SetIfVersion {
            path: path.clone(),
            envelope,
            expected_version,
        })? {
            Response::Updated => Ok(version),
            Response::Error { message } => Err(message.into()),
            response => Err(unexpected(response).into()),
        }
    }

    /// Stores an envelope produced elsewhere, such as a target-generated
    /// value, through the same conditional write as local edits.
    pub fn set_envelope_if_version(
        &mut self,
        path: &SecretPath,
        envelope: StoredSecret,
        expected_version: Option<Vec<u8>>,
    ) -> io::Result<()> {
        match self.exchange(&Request::SetIfVersion {
            path: path.clone(),
            envelope,
            expected_version,
        })? {
            Response::Updated => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn remove_if_version(
        &mut self,
        path: &SecretPath,
        expected_version: Vec<u8>,
    ) -> io::Result<bool> {
        match self.exchange(&Request::RemoveIfVersion {
            path: path.clone(),
            expected_version,
        })? {
            Response::Removed { existed } => Ok(existed),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    /// The schema document the backend evaluated, its age in milliseconds,
    /// and whether requests wait for an operator.
    pub fn schema_document(&mut self) -> io::Result<(Option<String>, u64, bool)> {
        match self.exchange(&Request::GetSchema)? {
            Response::SchemaDocument {
                json,
                age_ms,
                waiting,
            } => Ok((json, age_ms, waiting)),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn register_frontend(&mut self) -> io::Result<()> {
        match self.exchange(&Request::RegisterFrontend)? {
            Response::FrontendRegistered => Ok(()),
            response => Err(unexpected(response)),
        }
    }

    pub fn poll_and_claim(&mut self) -> io::Result<Option<(ApprovalRequest, u64)>> {
        Ok(self
            .poll_and_claim_step()?
            .map(|(request, lease_id, _)| (request, lease_id)))
    }

    /// Like [`Self::poll_and_claim`], with the procedure step the backend
    /// assigned to the claimed request, if any.
    pub fn poll_and_claim_step(
        &mut self,
    ) -> io::Result<Option<(ApprovalRequest, u64, Option<ProcedureStep>)>> {
        let (requests, mut procedures) = match self.exchange(&Request::PollApprovals)? {
            Response::Approvals {
                requests,
                procedures,
            } => (requests, procedures),
            response => return Err(unexpected(response)),
        };
        for request in requests {
            match self.exchange(&Request::ClaimApproval {
                request_id: request.id.clone(),
                lease_ms: 300_000,
            })? {
                Response::ApprovalClaimed { lease_id, .. } => {
                    let step = procedures.remove(&request.id);
                    return Ok(Some((request, lease_id, step)));
                }
                // Another frontend can win a claim after our availability
                // snapshot. Try the remaining requests without losing them.
                Response::Error { message } if message == "approval request is unavailable" => {
                    continue
                }
                Response::Error { message } => return Err(io::Error::other(message)),
                response => return Err(unexpected(response)),
            }
        }
        Ok(None)
    }

    pub fn has_pending_approvals(&mut self) -> io::Result<bool> {
        match self.exchange(&Request::PollApprovals)? {
            Response::Approvals { requests, .. } => Ok(!requests.is_empty()),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn submit_approval(&mut self, request: ApprovalRequest) -> io::Result<()> {
        match self.exchange(&Request::SubmitApproval { request })? {
            Response::ApprovalState {
                state: ApprovalStatus::Pending,
            } => Ok(()),
            Response::ApprovalState { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    /// Asks the backend to queue a deployment of every deployable value of
    /// `target` for the registered frontends.
    pub fn request_deployment(
        &mut self,
        target: &str,
        allow_partial: bool,
    ) -> io::Result<ApprovalRequest> {
        self.request_deployment_in(target, allow_partial, None)
    }

    /// Like [`Self::request_deployment`], as the next step of the procedure
    /// whose token this process inherited.
    pub fn request_deployment_in(
        &mut self,
        target: &str,
        allow_partial: bool,
        procedure: Option<String>,
    ) -> io::Result<ApprovalRequest> {
        match self.exchange(&Request::RequestDeployment {
            target: target.to_owned(),
            allow_partial,
            procedure,
        })? {
            Response::DeploymentRequested { request } => Ok(request),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn approval_status(&mut self, request_id: &str) -> io::Result<ApprovalStatus> {
        match self.exchange(&Request::ApprovalStatus {
            request_id: request_id.to_owned(),
        })? {
            Response::ApprovalState { state } => Ok(state),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn resolve(
        &mut self,
        request_id: String,
        lease_id: u64,
        approved: bool,
        message: Option<String>,
    ) -> io::Result<()> {
        let decision = if approved {
            Decision::Approved
        } else {
            Decision::Rejected
        };
        match self.exchange(&Request::ResolveApproval {
            request_id,
            lease_id,
            decision,
            message,
        })? {
            Response::ApprovalResolved => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn renew(&mut self, request_id: String, lease_id: u64) -> io::Result<()> {
        self.renew_for(request_id, lease_id, 300_000)
    }

    pub fn renew_for(
        &mut self,
        request_id: String,
        lease_id: u64,
        lease_ms: u64,
    ) -> io::Result<()> {
        match self.exchange(&Request::RenewApproval {
            request_id,
            lease_id,
            lease_ms,
        })? {
            Response::ApprovalRenewed { .. } => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn set(
        &mut self,
        path: &SecretPath,
        plaintext: &[u8],
        recipients: &[Recipient<'_>],
        provider: &impl CryptoProvider,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.set_with_expected(path, plaintext, recipients, provider, None)
    }

    pub fn set_if_version(
        &mut self,
        path: &SecretPath,
        plaintext: &[u8],
        recipients: &[Recipient<'_>],
        provider: &impl CryptoProvider,
        expected_version: Option<Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.set_with_expected(
            path,
            plaintext,
            recipients,
            provider,
            Some(expected_version),
        )
    }

    fn set_with_expected(
        &mut self,
        path: &SecretPath,
        plaintext: &[u8],
        recipients: &[Recipient<'_>],
        provider: &impl CryptoProvider,
        expected_version: Option<Option<Vec<u8>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = encrypt_secret(&path.to_string(), plaintext, recipients, provider)?;
        let envelope = StoredSecret {
            format_version: encrypted.format_version,
            version_id: encrypted.version_id,
            recipient_ids: encrypted.recipient_ids,
            recipient_refs: vec![],
            age_ciphertext: encrypted.age_ciphertext,
            public_key: None,
        };
        let request = match expected_version {
            Some(expected_version) => Request::SetIfVersion {
                path: path.clone(),
                envelope,
                expected_version,
            },
            None => Request::Set {
                path: path.clone(),
                envelope,
            },
        };
        match self.exchange(&request)? {
            Response::Updated => Ok(()),
            Response::Error { message } => Err(message.into()),
            response => Err(unexpected(response).into()),
        }
    }

    pub(crate) fn exchange(&mut self, request: &Request) -> io::Result<Response> {
        write_json(&mut self.stream, request)?;
        read_json(&mut self.stream)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend closed the connection",
            )
        })
    }
}

fn unexpected(response: Response) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected backend response: {response:?}"),
    )
}
