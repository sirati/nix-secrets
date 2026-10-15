//! Decides when a waiting waiter refreshes its systemd status and logs.

use std::path::PathBuf;
use std::time::Duration;

/// Minimum spacing between two status refreshes with an unchanged missing set.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(30);
/// Spacing between two log lines while still waiting.
pub const LOG_INTERVAL: Duration = Duration::from_secs(600);
/// Paths named in one status/log line before the rest is summarised.
const MAX_LISTED: usize = 8;

/// What the waiter should emit after one poll.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Emit {
    pub status: Option<String>,
    pub log: Option<String>,
}

#[derive(Debug, Default)]
pub struct Progress {
    missing: Vec<PathBuf>,
    last_status: Option<Duration>,
    last_log: Option<Duration>,
}

pub fn waiting_text(missing: &[PathBuf], elapsed: Duration) -> String {
    let mut listed: Vec<String> = missing
        .iter()
        .take(MAX_LISTED)
        .map(|path| path.display().to_string())
        .collect();
    if missing.len() > MAX_LISTED {
        listed.push(format!("+{} more", missing.len() - MAX_LISTED));
    }
    format!(
        "still waiting for {} ({}s)",
        listed.join(", "),
        elapsed.as_secs()
    )
}

impl Progress {
    /// Records one poll result; `elapsed` is the time since waiting began.
    pub fn observe(&mut self, missing: &[PathBuf], elapsed: Duration) -> Emit {
        if missing.is_empty() {
            return Emit::default();
        }
        let changed = self.missing.as_slice() != missing;
        if changed {
            self.missing = missing.to_vec();
        }
        let due = |last: Option<Duration>, interval: Duration| {
            last.is_none_or(|last| elapsed.saturating_sub(last) >= interval)
        };
        let text = waiting_text(missing, elapsed);
        let mut emit = Emit::default();
        if changed || due(self.last_status, STATUS_INTERVAL) {
            self.last_status = Some(elapsed);
            emit.status = Some(text.clone());
        }
        if due(self.last_log, LOG_INTERVAL) {
            self.last_log = Some(elapsed);
            emit.log = Some(format!("secrets-ready-waiter: {text}"));
        }
        emit
    }

    /// Whether a waiting status was ever published.
    pub fn waited(&self) -> bool {
        self.last_status.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn formats_paths_and_seconds() {
        assert_eq!(
            waiting_text(&paths(&["/a", "/b"]), Duration::from_millis(42_900)),
            "still waiting for /a, /b (42s)"
        );
    }

    #[test]
    fn summarises_long_lists() {
        let many: Vec<PathBuf> = (0..11).map(|n| PathBuf::from(format!("/s{n}"))).collect();
        let text = waiting_text(&many, Duration::ZERO);
        assert!(text.contains("/s7, +3 more (0s)"), "{text}");
        assert!(!text.contains("/s8"));
    }

    #[test]
    fn first_poll_sets_status_and_logs() {
        let mut progress = Progress::default();
        let emit = progress.observe(&paths(&["/a"]), Duration::ZERO);
        assert_eq!(emit.status.as_deref(), Some("still waiting for /a (0s)"));
        assert_eq!(
            emit.log.as_deref(),
            Some("secrets-ready-waiter: still waiting for /a (0s)")
        );
        assert!(progress.waited());
    }

    #[test]
    fn unchanged_set_refreshes_status_at_most_every_thirty_seconds() {
        let mut progress = Progress::default();
        let missing = paths(&["/a"]);
        progress.observe(&missing, Duration::ZERO);
        for second in 1..30 {
            assert_eq!(
                progress.observe(&missing, Duration::from_secs(second)),
                Emit::default()
            );
        }
        let emit = progress.observe(&missing, Duration::from_secs(30));
        assert_eq!(emit.status.as_deref(), Some("still waiting for /a (30s)"));
        assert_eq!(emit.log, None);
    }

    #[test]
    fn changed_set_refreshes_status_immediately() {
        let mut progress = Progress::default();
        progress.observe(&paths(&["/a", "/b"]), Duration::ZERO);
        let emit = progress.observe(&paths(&["/b"]), Duration::from_secs(1));
        assert_eq!(emit.status.as_deref(), Some("still waiting for /b (1s)"));
        assert_eq!(emit.log, None);
    }

    #[test]
    fn logs_again_after_ten_minutes() {
        let mut progress = Progress::default();
        let missing = paths(&["/a"]);
        progress.observe(&missing, Duration::ZERO);
        assert_eq!(
            progress.observe(&missing, Duration::from_secs(599)).log,
            None
        );
        assert!(
            progress
                .observe(&missing, Duration::from_secs(600))
                .log
                .is_some()
        );
        assert_eq!(
            progress.observe(&missing, Duration::from_secs(601)).log,
            None
        );
    }

    #[test]
    fn nothing_missing_emits_nothing() {
        let mut progress = Progress::default();
        assert_eq!(progress.observe(&[], Duration::ZERO), Emit::default());
        assert!(!progress.waited());
    }
}
