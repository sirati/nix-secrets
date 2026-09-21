use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::{
    ApprovalRequest, ApprovalStatus, Decision, EncryptedSecret as StoredSecret, Request, Response,
    SecretPath,
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
        let encrypted = encrypt_secret(&path.to_string(), plaintext, recipients, provider)?;
        let envelope = StoredSecret {
            format_version: encrypted.format_version,
            version_id: encrypted.version_id,
            recipient_ids: encrypted.recipient_ids,
            age_ciphertext: encrypted.age_ciphertext,
        };
        match self.exchange(&Request::Set {
            path: path.clone(),
            envelope,
        })? {
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
