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

pub struct Backend {
    socket_path: PathBuf,
    listener: UnixListener,
    schema: Arc<Schema>,
    store: Arc<SecretStore>,
    profiles: Arc<ProfileStore>,
    broker: Arc<Mutex<ApprovalBroker>>,
    next_session: Arc<AtomicU64>,
    feed: Arc<Feed>,
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
            store: Arc::new(store),
            profiles: Arc::new(profiles),
            broker: Arc::new(Mutex::new(ApprovalBroker::default())),
            next_session: Arc::new(AtomicU64::new(1)),
            feed: Arc::new(Feed::default()),
        })
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
            let store = Arc::clone(&self.store);
            let profiles = Arc::clone(&self.profiles);
            let broker = Arc::clone(&self.broker);
            let feed = Arc::clone(&self.feed);
            let session = self.next_session.fetch_add(1, Ordering::Relaxed);
            thread::spawn(move || {
                let _ = handle_client(stream, &schema, &store, &profiles, &broker, &feed, session);
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

fn handle_client(
    mut stream: UnixStream,
    schema: &Schema,
    store: &SecretStore,
    profiles: &ProfileStore,
    broker: &Mutex<ApprovalBroker>,
    feed: &Feed,
    session: u64,
) -> io::Result<()> {
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
            request => request,
        };
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
            } => store
                .set_public_key_if_version(schema, &path, public_key, &expected_version)
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
            } => with_broker(broker, |state| {
                state
                    .resolve(session, &request_id, lease_id, decision)
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
            Request::SubscribeChanges | Request::Commit { .. } => unreachable!("handled above"),
        }
        .unwrap_or_else(|error| Response::Error {
            message: error.to_string(),
        });
        if !matches!(response, Response::Error { .. }) {
            if let Some(update) = update {
                feed.publish(update);
            }
        }
        write_json(&mut stream, &response)?;
    }
    Ok(())
}

mod broker;
use broker::with_broker;

mod socket_path;
use socket_path::prepare_socket_path;
