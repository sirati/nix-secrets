use crate::framing::{read_json, write_json};
use crate::{ApprovalBroker, BrokerError, ProfileStore, Schema, SecretStore};
use rustix::net::sockopt::socket_peercred;
use rustix::process::geteuid;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

mod event_after;
use event_after::event_after_success;
mod feed;
pub use feed::BackendEvent;
use feed::Feed;
mod protocol;
pub use protocol::{Request, Response};
mod commit;
mod secrets;
pub use secrets::NO_OPERATOR;

pub struct Backend {
    socket_path: PathBuf,
    listener: UnixListener,
    schema: Arc<Schema>,
    schema_loader: Option<Arc<dyn Fn() -> Result<Schema, String> + Send + Sync>>,
    store: Arc<SecretStore>,
    profiles: Arc<ProfileStore>,
    broker: Arc<Mutex<ApprovalBroker>>,
    next_session: Arc<AtomicU64>,
    feed: Arc<Feed>,
    operators: Arc<secrets::Operators>,
}

impl Backend {
    pub fn bind(
        socket_path: impl Into<PathBuf>,
        schema: Schema,
        store: SecretStore,
    ) -> io::Result<Self> {
        let socket_path = socket_path.into();
        let repository = store
            .path()
            .parent()
            .ok_or_else(|| io::Error::other("store has no repository directory"))?;
        let profiles = ProfileStore::new(repository)?;
        prepare_socket_path(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            socket_path,
            listener,
            schema: Arc::new(schema),
            schema_loader: None,
            store: Arc::new(store),
            profiles: Arc::new(profiles),
            broker: Arc::new(Mutex::new(ApprovalBroker::default())),
            next_session: Arc::new(AtomicU64::new(1)),
            feed: Arc::new(Feed::default()),
            operators: Arc::new(secrets::Operators::default()),
        })
    }

    /// Reload trusted repository metadata before validating a store mutation.
    /// The client cannot supply the schema used to authorize its write.
    pub fn with_schema_loader<F>(mut self, loader: F) -> Self
    where F: Fn() -> Result<Schema, String> + Send + Sync + 'static {
        self.schema_loader = Some(Arc::new(loader));
        self
    }

    pub fn serve(self) -> io::Result<()> {
        for stream in self.listener.incoming() {
            let stream = stream?;
            let peer = socket_peercred(&stream)
                .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
            if peer.uid != geteuid() {
                continue;
            }
            let schema = Arc::clone(&self.schema);
            let schema_loader = self.schema_loader.clone();
            let store = Arc::clone(&self.store);
            let profiles = Arc::clone(&self.profiles);
            let broker = Arc::clone(&self.broker);
            let feed = Arc::clone(&self.feed);
            let operators = Arc::clone(&self.operators);
            let peer_pid = rustix::process::Pid::as_raw(Some(peer.pid)) as u32;
            let session = self.next_session.fetch_add(1, Ordering::Relaxed);
            thread::spawn(move || {
                let context = Context {
                    schema: &schema,
                    schema_loader: schema_loader.as_deref(),
                    store: &store,
                    profiles: &profiles,
                    broker: &broker,
                    feed: &feed,
                    operators: &operators,
                    session,
                    peer_pid,
                };
                let _ = handle_client(stream, &context);
                if let Ok(mut state) = broker.lock() {
                    state.disconnect(session);
                }
            });
        }
        Ok(())
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

struct Context<'a> {
    schema: &'a Schema,
    schema_loader: Option<&'a (dyn Fn() -> Result<Schema, String> + Send + Sync)>,
    store: &'a SecretStore,
    profiles: &'a ProfileStore,
    broker: &'a Mutex<ApprovalBroker>,
    feed: &'a Feed,
    operators: &'a secrets::Operators,
    session: u64,
    /// The connected process, from the kernel's peer credentials.
    peer_pid: u32,
}

fn handle_client(mut stream: UnixStream, context: &Context<'_>) -> io::Result<()> {
    let Context {
        schema,
        schema_loader,
        store,
        profiles,
        broker,
        feed,
        operators,
        session,
        peer_pid,
    } = *context;
    while let Some(request) = read_json::<Request>(&mut stream)? {
        if matches!(request, Request::SubscribeChanges) {
            let receiver = feed.subscribe();
            write_json(&mut stream, &Response::Subscribed)?;
            loop {
                match receiver.recv_timeout(Duration::from_secs(60)) {
                    Ok(update) => write_json(&mut stream, &Response::Change { update })?,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        write_json(&mut stream, &Response::Heartbeat)?;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                }
            }
        }
        let request = match request {
            Request::Commit {
                options,
                forward_agent,
            } => {
                let response = commit::commit(&mut stream, store, options, forward_agent)?;
                write_json(&mut stream, &response)?;
                continue;
            }
            // The connection becomes the TUI's operator channel for good.
            Request::AttachOperator => return secrets::attach(&mut stream, operators, session),
            Request::RequestSecrets {
                identifiers,
                reason,
            } => {
                secrets::request(&mut stream, operators, peer_pid, identifiers, reason)?;
                continue;
            }
            Request::RequestSshSignature { request, reason } => {
                secrets::request_signature(&mut stream, operators, peer_pid, request, reason)?;
                continue;
            }
            request => request,
        };
        let fresh_schema = if matches!(request,
            Request::Set { .. } | Request::SetIfVersion { .. }
            | Request::Remove { .. } | Request::RemoveIfVersion { .. }
            | Request::SetGeneratedPublicKeyIfVersion { .. }
            | Request::SetPublicKeyIfVersion { .. }
            | Request::SetPublicInfoIfVersion { .. }
            | Request::RemovePublicInfoIfVersion { .. }
        ) {
            match schema_loader.map(|load| load()).transpose() {
                Ok(schema) => schema,
                Err(message) => {
                    write_json(&mut stream, &Response::Error {
                        message: format!("reloading repository schema failed: {message}"),
                    })?;
                    continue;
                }
            }
        } else { None };
        let schema = fresh_schema.as_ref().unwrap_or(schema);
        let update = event_after_success(&request, schema);
        let response = match request {
            Request::Get { path } => store
                .get(&path)
                .map(|envelope| Response::Secret { envelope })
                .map_err(|error| error.to_string()),
            Request::CommitState { path } => store
                .commit_state(&path)
                .map(|state| Response::CommitState { state })
                .map_err(|error| error.to_string()),
            Request::List => store
                .list()
                .map(|entries| Response::Secrets { entries })
                .map_err(|error| error.to_string()),
            Request::ListProfiles => profiles
                .list()
                .map(|snapshot| Response::Profiles { snapshot })
                .map_err(|error| error.to_string()),
            Request::SaveProfile {
                name,
                profile,
                expected_revision,
            } => profiles
                .save(&name, profile, expected_revision)
                .map(|snapshot| Response::Profiles { snapshot })
                .map_err(|error| error.to_string()),
            Request::DeleteProfile {
                name,
                expected_revision,
            } => profiles
                .delete(&name, expected_revision)
                .map(|snapshot| Response::Profiles { snapshot })
                .map_err(|error| error.to_string()),
            Request::Set { path, envelope } => store
                .set(schema, &path, envelope)
                .map(|()| Response::Updated)
                .map_err(|error| error.to_string()),
            Request::SetIfVersion {
                path,
                envelope,
                expected_version,
            } => store
                .set_if_version(schema, &path, envelope, expected_version.as_deref())
                .map(|()| Response::Updated)
                .map_err(|error| error.to_string()),
            Request::Remove { path } => store
                .remove(schema, &path)
                .map(|existed| Response::Removed { existed })
                .map_err(|error| error.to_string()),
            Request::RemoveIfVersion {
                path,
                expected_version,
            } => store
                .remove_if_version(schema, &path, &expected_version)
                .map(|existed| Response::Removed { existed })
                .map_err(|error| error.to_string()),
            Request::GetGeneratedPublicKey { path } => store
                .generated_public_key(&path)
                .map(|value| Response::GeneratedPublicKey { value })
                .map_err(|error| error.to_string()),
            Request::SetGeneratedPublicKeyIfVersion {
                path,
                value,
                expected_version,
            } => store
                .set_generated_public_key_if_version(
                    schema,
                    &path,
                    value,
                    expected_version.as_deref(),
                )
                .map(|()| Response::Updated)
                .map_err(|error| error.to_string()),
            Request::SetPublicKeyIfVersion {
                path,
                public_key,
                expected_version,
                expected_public_key,
            } => store
                .set_public_key_if_version(schema, &path, public_key, &expected_version, expected_public_key.as_deref())
                .map(|()| Response::Updated)
                .map_err(|error| error.to_string()),
            Request::ListPublicInfo => store
                .list_public_info()
                .map(|entries| Response::PublicInfoEntries { entries })
                .map_err(|error| error.to_string()),
            Request::GetPublicInfo { shared_id } => store
                .get_public_info(&shared_id)
                .map(|value| Response::PublicInfo { value })
                .map_err(|error| error.to_string()),
            Request::SetPublicInfoIfVersion {
                path,
                value,
                expected_version,
            } => store
                .set_public_info_if_version(schema, &path, value, expected_version.as_deref())
                .map(|()| Response::Updated)
                .map_err(|error| error.to_string()),
            Request::RemovePublicInfoIfVersion {
                path,
                expected_version,
            } => store
                .remove_public_info_if_version(schema, &path, &expected_version)
                .map(|existed| Response::Removed { existed })
                .map_err(|error| error.to_string()),
            Request::RegisterFrontend => with_broker(broker, |state| {
                state
                    .register(session)
                    .map(|()| Response::FrontendRegistered)
            }),
            Request::PollApprovals => with_broker(broker, |state| {
                state
                    .pending(session)
                    .map(|requests| Response::Approvals { requests })
            }),
            Request::SubmitApproval { request } => with_broker(broker, |state| {
                state
                    .submit(request)
                    .map(|state| Response::ApprovalState { state })
            }),
            Request::ClaimApproval {
                request_id,
                lease_ms,
            } => with_broker(broker, |state| {
                state
                    .claim(session, &request_id, Duration::from_millis(lease_ms))
                    .map(|claim| Response::ApprovalClaimed {
                        lease_id: claim.lease_id,
                        expires_in_ms: claim.expires_in_ms,
                    })
            }),
            Request::RenewApproval {
                request_id,
                lease_id,
                lease_ms,
            } => with_broker(broker, |state| {
                state
                    .renew(
                        session,
                        &request_id,
                        lease_id,
                        Duration::from_millis(lease_ms),
                    )
                    .map(|expires_in_ms| Response::ApprovalRenewed { expires_in_ms })
            }),
            Request::ResolveApproval {
                request_id,
                lease_id,
                decision,
                message,
            } => with_broker(broker, |state| {
                state
                    .resolve(session, &request_id, lease_id, decision, message)
                    .map(|()| Response::ApprovalResolved)
            }),
            Request::CancelApproval { request_id } => with_broker(broker, |state| {
                state
                    .cancel(&request_id)
                    .map(|()| Response::ApprovalCancelled)
            }),
            Request::ApprovalStatus { request_id } => with_broker(broker, |state| {
                state
                    .status(&request_id)
                    .map(|state| Response::ApprovalState { state })
            }),
            Request::CommitSummary => commit::repository(store)
                .and_then(|repository| repository.summary())
                .map(|summary| Response::CommitSummary { summary }),
            Request::AgentReply { .. } => Err("no signing request is pending".into()),
            Request::AnswerSecretRequest { .. } => {
                Err("answers are accepted only on an attached operator connection".into())
            }
            Request::EndSecretSession => Err("no secret session is open".into()),
            Request::RequestDeployment {
                target,
                allow_partial,
            } => deployment::request(schema, broker, target, allow_partial),
            Request::SubscribeChanges
            | Request::Commit { .. }
            | Request::AttachOperator
            | Request::RequestSecrets { .. }
            | Request::RequestSshSignature { .. } => unreachable!("handled above"),
        }
        .unwrap_or_else(|error| Response::Error {
            message: error.to_string(),
        });
        if !matches!(response, Response::Error { .. }) {
            if let Some(update) = update {
                feed.publish(update);
            }
        }
        // Its id is chosen here, so the event follows the response.
        if let Response::DeploymentRequested { request } = &response {
            feed.publish(BackendEvent::ApprovalRequested {
                request: request.clone(),
            });
        }
        write_json(&mut stream, &response)?;
    }
    Ok(())
}

mod broker;
use broker::with_broker;
mod deployment;

mod socket_path;
use socket_path::prepare_socket_path;
