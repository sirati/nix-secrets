use super::*;
use nix_secrets_core::git::agent::{relay, FAILURE};
use nix_secrets_core::git::{CommitOptions, CommitResult, CommitSummary};
use std::path::Path;

impl BackendClient {
    pub fn commit_summary(&mut self) -> io::Result<CommitSummary> {
        match self.exchange(&Request::CommitSummary)? {
            Response::CommitSummary { summary } => Ok(summary),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    /// Commits on the backend. With `agent`, the backend's signing requests
    /// are answered by that local ssh-agent, filtered here as well.
    pub fn commit(
        &mut self,
        options: CommitOptions,
        agent: Option<&Path>,
    ) -> io::Result<Result<CommitResult, String>> {
        let mut response = self.exchange(&Request::Commit {
            options,
            forward_agent: agent.is_some(),
        })?;
        loop {
            match response {
                Response::AgentRequest { message } => {
                    let reply = match agent {
                        // An unreachable agent reads as a refusal, so git
                        // reports a signing failure rather than hanging.
                        Some(agent) => {
                            relay(agent, &message).unwrap_or_else(|_| FAILURE[4..].to_vec())
                        }
                        None => FAILURE[4..].to_vec(),
                    };
                    response = self.exchange(&Request::AgentReply { message: reply })?;
                }
                Response::Committed { result } => return Ok(Ok(result)),
                Response::Error { message } => return Ok(Err(message)),
                response => return Err(unexpected(response)),
            }
        }
    }
}
