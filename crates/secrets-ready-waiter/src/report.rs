//! `--report-waiting`: names the secrets waiters that have been waiting for
//! longer than a threshold, so a timer unit can surface them as a failure.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub const UNIT_PREFIX: &str = "secrets-ready-waiter-";
pub const UNIT_SUFFIX: &str = ".service";
const UNIT_PATTERN: &str = "secrets-ready-waiter-*.service";
const PROPERTIES: &str = "--property=Id,ActiveState,InactiveExitTimestampMonotonic,StatusText";

#[derive(Debug, Eq, PartialEq)]
pub struct WaiterUnit {
    pub id: String,
    pub active_state: String,
    /// CLOCK_MONOTONIC microseconds at which the unit started activating.
    pub inactive_exit_us: u64,
    pub status_text: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Waiting {
    pub id: String,
    pub waited: Duration,
    pub status_text: String,
}

/// Parses `systemctl show --property=…` output: blank-line separated blocks
/// of `Key=Value` lines. Blocks for other units are ignored.
pub fn parse_show(output: &str) -> Result<Vec<WaiterUnit>, String> {
    let mut units = Vec::new();
    for block in output.split("\n\n") {
        let mut properties = HashMap::new();
        for line in block.lines().filter(|line| !line.is_empty()) {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("malformed systemctl show line: {line:?}"))?;
            properties.insert(key, value);
        }
        let Some(id) = properties.get("Id") else {
            continue;
        };
        if !(id.starts_with(UNIT_PREFIX) && id.ends_with(UNIT_SUFFIX)) {
            continue;
        }
        let active_state = properties
            .get("ActiveState")
            .ok_or_else(|| format!("{id}: systemctl show lacks ActiveState"))?;
        let inactive_exit_us = match properties.get("InactiveExitTimestampMonotonic") {
            None | Some(&"") => 0,
            Some(value) => value
                .parse()
                .map_err(|_| format!("{id}: invalid InactiveExitTimestampMonotonic {value:?}"))?,
        };
        units.push(WaiterUnit {
            id: (*id).to_owned(),
            active_state: (*active_state).to_owned(),
            inactive_exit_us,
            status_text: properties
                .get("StatusText")
                .copied()
                .unwrap_or("")
                .to_owned(),
        });
    }
    Ok(units)
}

/// Waiters still activating for at least `after` (`after == 0`: any waiter
/// that is waiting at all).
pub fn overdue(units: Vec<WaiterUnit>, now_us: u64, after: Duration) -> Vec<Waiting> {
    units
        .into_iter()
        .filter(|unit| unit.active_state == "activating")
        .map(|unit| Waiting {
            waited: Duration::from_micros(now_us.saturating_sub(unit.inactive_exit_us)),
            id: unit.id,
            status_text: unit.status_text,
        })
        .filter(|waiting| waiting.waited >= after)
        .collect()
}

pub fn report_line(waiting: &Waiting) -> String {
    let status = if waiting.status_text.is_empty() {
        "no status reported"
    } else {
        &waiting.status_text
    };
    format!(
        "still waiting for secrets: {} for {}s: {status}",
        waiting.id,
        waiting.waited.as_secs()
    )
}

fn monotonic_now_us() -> Result<u64, String> {
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .map_err(|error| format!("reading CLOCK_MONOTONIC: {error}"))?;
    let seconds = u64::try_from(now.tv_sec()).map_err(|_| "negative monotonic clock")?;
    let nanos = u64::try_from(now.tv_nsec()).map_err(|_| "negative monotonic clock")?;
    Ok(seconds * 1_000_000 + nanos / 1_000)
}

fn show_waiters(systemctl: &Path) -> Result<String, String> {
    let output = Command::new(systemctl)
        .env_clear()
        .args(["show", "--no-pager", PROPERTIES, "--", UNIT_PATTERN])
        .output()
        .map_err(|error| format!("running {}: {error}", systemctl.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} show failed ({}): {}",
            systemctl.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "systemctl show output is not UTF-8".into())
}

/// Exit codes: 0 nothing overdue, 2 at least one waiter overdue, 1 error.
pub fn run(systemctl: &Path, after: Duration) -> Result<u8, String> {
    if !systemctl.is_absolute() {
        return Err("--systemctl must be an absolute path".into());
    }
    let units = parse_show(&show_waiters(systemctl)?)?;
    let waiting = overdue(units, monotonic_now_us()?, after);
    if waiting.is_empty() {
        match after.as_secs() {
            0 => println!("no secrets waiter is waiting"),
            seconds => println!("no secrets waiter has been waiting for {seconds}s or longer"),
        }
        return Ok(0);
    }
    for waiter in &waiting {
        println!("{}", report_line(waiter));
    }
    Ok(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOW: &str = "\
Id=secrets-ready-waiter-mail.service
ActiveState=activating
InactiveExitTimestampMonotonic=5000000
StatusText=still waiting for /persistent/secrets/mail/service/password (95s)

Id=secrets-ready-waiter-dns.service
ActiveState=active
InactiveExitTimestampMonotonic=1000000
StatusText=

Id=other.service
ActiveState=activating
InactiveExitTimestampMonotonic=1
StatusText=
";

    fn unit(state: &str, start_us: u64) -> WaiterUnit {
        WaiterUnit {
            id: "secrets-ready-waiter-x.service".into(),
            active_state: state.into(),
            inactive_exit_us: start_us,
            status_text: "s".into(),
        }
    }

    #[test]
    fn parses_systemctl_show_blocks() {
        let units = parse_show(SHOW).unwrap();
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].id, "secrets-ready-waiter-mail.service");
        assert_eq!(units[0].active_state, "activating");
        assert_eq!(units[0].inactive_exit_us, 5_000_000);
        assert!(units[0].status_text.ends_with("password (95s)"));
        assert_eq!(units[1].status_text, "");
    }

    #[test]
    fn parses_empty_output() {
        assert_eq!(parse_show("").unwrap(), Vec::new());
        assert_eq!(parse_show("\n\n\n").unwrap().len(), 0);
    }

    #[test]
    fn status_text_may_contain_equals_signs() {
        let units = parse_show(
            "Id=secrets-ready-waiter-a.service\nActiveState=activating\nStatusText=a=b\n",
        )
        .unwrap();
        assert_eq!(units[0].status_text, "a=b");
        assert_eq!(units[0].inactive_exit_us, 0);
    }

    #[test]
    fn rejects_malformed_waiter_blocks() {
        assert!(parse_show("Id=secrets-ready-waiter-a.service\ngarbage\n").is_err());
        assert!(parse_show("Id=secrets-ready-waiter-a.service\nStatusText=\n").is_err());
        assert!(
            parse_show(
                "Id=secrets-ready-waiter-a.service\nActiveState=activating\nInactiveExitTimestampMonotonic=x\n"
            )
            .is_err()
        );
    }

    #[test]
    fn reports_waiters_waiting_at_least_the_threshold() {
        let now = 1_000_000_000;
        let longer = overdue(vec![unit("activating", 0)], now, Duration::from_secs(900));
        assert_eq!(longer.len(), 1);
        assert_eq!(longer[0].waited, Duration::from_secs(1000));
        let shorter = overdue(
            vec![unit("activating", now - 899_000_000)],
            now,
            Duration::from_secs(900),
        );
        assert!(shorter.is_empty());
    }

    #[test]
    fn ignores_waiters_that_are_not_activating() {
        for state in ["active", "inactive", "failed", "deactivating"] {
            assert!(overdue(vec![unit(state, 0)], 1_000_000_000, Duration::ZERO).is_empty());
        }
    }

    #[test]
    fn zero_threshold_reports_any_waiting_waiter() {
        let now = 10_000_000;
        let waiting = overdue(vec![unit("activating", now)], now, Duration::ZERO);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].waited, Duration::ZERO);
    }

    #[test]
    fn report_line_contract() {
        let mut waiting = Waiting {
            id: "secrets-ready-waiter-mail.service".into(),
            waited: Duration::from_millis(1_234_567),
            status_text: "still waiting for /p (1234s)".into(),
        };
        assert_eq!(
            report_line(&waiting),
            "still waiting for secrets: secrets-ready-waiter-mail.service for 1234s: still waiting for /p (1234s)"
        );
        waiting.status_text.clear();
        assert!(report_line(&waiting).ends_with(": no status reported"));
    }

    #[test]
    fn relative_systemctl_is_an_error() {
        assert!(run(Path::new("systemctl"), Duration::ZERO).is_err());
    }
}
