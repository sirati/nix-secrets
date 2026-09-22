use crate::approval_types::{ApprovalRequest, ApprovalStatus, Claim, Decision};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

const MAX_REQUESTS: usize = 4096;
const MAX_FRONTENDS: usize = 128;
const MAX_QUEUE: usize = 4096;
const MAX_LEASE: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Eq, PartialEq)]
pub enum BrokerError {
    Invalid(&'static str),
    Full,
    Unknown,
    Unavailable,
    WrongLease,
}

struct Lease {
    id: u64,
    owner: u64,
    expires: Instant,
}
struct Entry {
    request: ApprovalRequest,
    state: State,
}
enum State {
    Pending,
    Claimed(Lease),
    Resolved(Decision),
    Cancelled,
}
#[derive(Default)]
struct Frontend {
    queued: VecDeque<String>,
    known: BTreeSet<String>,
}

pub struct ApprovalBroker {
    entries: BTreeMap<String, Entry>,
    frontends: BTreeMap<u64, Frontend>,
    next_lease: u64,
}

impl Default for ApprovalBroker {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            frontends: BTreeMap::new(),
            next_lease: 1,
        }
    }
}

impl ApprovalBroker {
    pub fn register(&mut self, session: u64) -> Result<(), BrokerError> {
        self.reclaim();
        if !self.frontends.contains_key(&session) && self.frontends.len() >= MAX_FRONTENDS {
            return Err(BrokerError::Full);
        }
        let pending = self
            .entries
            .iter()
            .filter_map(|(id, entry)| matches!(entry.state, State::Pending).then_some(id.clone()))
            .collect::<Vec<_>>();
        let frontend = self.frontends.entry(session).or_default();
        for id in pending {
            queue(frontend, id);
        }
        Ok(())
    }

    pub fn submit(&mut self, request: ApprovalRequest) -> Result<ApprovalStatus, BrokerError> {
        request.validate().map_err(BrokerError::Invalid)?;
        self.reclaim();
        if let Some(entry) = self.entries.get(&request.id) {
            if entry.request != request {
                return Err(BrokerError::Invalid("request id collision"));
            }
            return Ok(status(entry));
        }
        if self.entries.len() >= MAX_REQUESTS {
            return Err(BrokerError::Full);
        }
        let id = request.id.clone();
        self.entries.insert(
            id.clone(),
            Entry {
                request,
                state: State::Pending,
            },
        );
        self.broadcast(id);
        Ok(ApprovalStatus::Pending)
    }

    pub fn pending(&mut self, session: u64) -> Result<Vec<ApprovalRequest>, BrokerError> {
        self.reclaim();
        let frontend = self
            .frontends
            .get_mut(&session)
            .ok_or(BrokerError::Unavailable)?;
        let ids = frontend.queued.drain(..).collect::<Vec<_>>();
        frontend.known.clear();
        Ok(ids
            .into_iter()
            .filter_map(|id| self.entries.get(&id))
            .filter(|entry| matches!(entry.state, State::Pending))
            .map(|entry| entry.request.clone())
            .collect())
    }

    pub fn claim(&mut self, session: u64, id: &str, lease: Duration) -> Result<Claim, BrokerError> {
        self.reclaim();
        if !self.frontends.contains_key(&session) {
            return Err(BrokerError::Unavailable);
        }
        if lease.is_zero() || lease > MAX_LEASE {
            return Err(BrokerError::Invalid("invalid lease duration"));
        }
        let entry = self.entries.get_mut(id).ok_or(BrokerError::Unknown)?;
        if !matches!(entry.state, State::Pending) {
            return Err(BrokerError::Unavailable);
        }
        let lease_id = self.next_lease;
        self.next_lease = self.next_lease.checked_add(1).unwrap_or(1);
        entry.state = State::Claimed(Lease {
            id: lease_id,
            owner: session,
            expires: Instant::now() + lease,
        });
        Ok(Claim {
            lease_id,
            expires_in_ms: millis(lease),
        })
    }

    pub fn resolve(
        &mut self,
        session: u64,
        id: &str,
        lease_id: u64,
        decision: Decision,
    ) -> Result<(), BrokerError> {
        self.reclaim();
        let entry = self.entries.get_mut(id).ok_or(BrokerError::Unknown)?;
        match &entry.state {
            State::Claimed(lease) if lease.owner == session && lease.id == lease_id => {
                entry.state = State::Resolved(decision);
                Ok(())
            }
            _ => Err(BrokerError::WrongLease),
        }
    }

    pub fn renew(
        &mut self,
        session: u64,
        id: &str,
        lease_id: u64,
        duration: Duration,
    ) -> Result<u64, BrokerError> {
        self.reclaim();
        if !self.frontends.contains_key(&session) {
            return Err(BrokerError::Unavailable);
        }
        if duration.is_zero() || duration > MAX_LEASE {
            return Err(BrokerError::Invalid("invalid lease duration"));
        }
        let entry = self.entries.get_mut(id).ok_or(BrokerError::Unknown)?;
        match &mut entry.state {
            State::Claimed(lease) if lease.owner == session && lease.id == lease_id => {
                lease.expires = Instant::now() + duration;
                Ok(millis(duration))
            }
            _ => Err(BrokerError::WrongLease),
        }
    }

    pub fn cancel(&mut self, id: &str) -> Result<(), BrokerError> {
        self.reclaim();
        let entry = self.entries.get_mut(id).ok_or(BrokerError::Unknown)?;
        entry.state = State::Cancelled;
        Ok(())
    }

    pub fn status(&mut self, id: &str) -> Result<ApprovalStatus, BrokerError> {
        self.reclaim();
        self.entries.get(id).map(status).ok_or(BrokerError::Unknown)
    }

    pub fn disconnect(&mut self, session: u64) {
        self.frontends.remove(&session);
        let ids = self
            .entries
            .iter_mut()
            .filter_map(|(id, entry)| match &entry.state {
                State::Claimed(lease) if lease.owner == session => {
                    entry.state = State::Pending;
                    Some(id.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for id in ids {
            self.broadcast(id);
        }
    }

    fn reclaim(&mut self) {
        let now = Instant::now();
        let ids = self
            .entries
            .iter_mut()
            .filter_map(|(id, entry)| match &entry.state {
                State::Claimed(lease) if lease.expires <= now => {
                    entry.state = State::Pending;
                    Some(id.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for id in ids {
            self.broadcast(id);
        }
    }

    fn broadcast(&mut self, id: String) {
        for frontend in self.frontends.values_mut() {
            queue(frontend, id.clone());
        }
    }
}

fn queue(frontend: &mut Frontend, id: String) {
    if frontend.known.insert(id.clone()) {
        if frontend.queued.len() == MAX_QUEUE
            && let Some(old) = frontend.queued.pop_front()
        {
            frontend.known.remove(&old);
        }
        frontend.queued.push_back(id);
    }
}

fn status(entry: &Entry) -> ApprovalStatus {
    match &entry.state {
        State::Pending => ApprovalStatus::Pending,
        State::Claimed(lease) => ApprovalStatus::Claimed {
            lease_id: lease.id,
            expires_in_ms: millis(lease.expires.saturating_duration_since(Instant::now())),
        },
        State::Resolved(decision) => ApprovalStatus::Resolved {
            decision: *decision,
        },
        State::Cancelled => ApprovalStatus::Cancelled,
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}
