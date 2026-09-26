mod profiles;
mod public_info;
mod subscription;
use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{
    ApprovalRequest, ApprovalStatus, BackendEvent, CommitState, Decision,
    EncryptedSecret as StoredSecret, GeneratedPublicKey, ProfileSnapshot, PublicInfoRecord,
    Request, Response, SecretPath, ViewProfile,
};
use nix_secrets_crypto::{encrypt_secret, CryptoProvider, Recipient};
use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;

pub struct BackendClient {
    stream: UnixStream,
}

impl BackendClient {
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
    ) -> io::Result<()> {
        match self.exchange(&Request::SetPublicKeyIfVersion {
            path: path.clone(),
            public_key,
            expected_version,
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

    pub fn register_frontend(&mut self) -> io::Result<()> {
        match self.exchange(&Request::RegisterFrontend)? {
            Response::FrontendRegistered => Ok(()),
            response => Err(unexpected(response)),
        }
    }

    pub fn poll_and_claim(&mut self) -> io::Result<Option<(ApprovalRequest, u64)>> {
        let requests = match self.exchange(&Request::PollApprovals)? {
            Response::Approvals { requests } => requests,
            response => return Err(unexpected(response)),
        };
        let Some(request) = requests.into_iter().next() else {
            return Ok(None);
        };
        match self.exchange(&Request::ClaimApproval {
            request_id: request.id.clone(),
            lease_ms: 300_000,
        })? {
            Response::ApprovalClaimed { lease_id, .. } => Ok(Some((request, lease_id))),
            Response::Error { .. } => Ok(None),
            response => Err(unexpected(response)),
        }
    }

    pub fn has_pending_approvals(&mut self) -> io::Result<bool> {
        match self.exchange(&Request::PollApprovals)? {
            Response::Approvals { requests } => Ok(!requests.is_empty()),
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

    pub fn resolve(&mut self, request_id: String, lease_id: u64, approved: bool) -> io::Result<()> {
        let decision = if approved {
            Decision::Approved
        } else {
            Decision::Rejected
        };
        match self.exchange(&Request::ResolveApproval {
            request_id,
            lease_id,
            decision,
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

    fn exchange(&mut self, request: &Request) -> io::Result<Response> {
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
