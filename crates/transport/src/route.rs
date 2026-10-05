//! Client-owned TCP forwards over the already authenticated backend SSH master.
//! Control commands never reconnect: a missing master is a hard failure.
use crate::hostkey::runner::{ProcessRunner, Runner};
use crate::HostKeyError;
use std::collections::HashMap;
use std::ffi::OsString;
use std::net::TcpListener;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug)]
pub struct BackendRoute {
    control: PathBuf,
    destination: OsString,
    forwards: Mutex<HashMap<(String, u16), Forward>>,
}
#[derive(Clone, Debug)]
struct Forward {
    port: u16,
    specification: String,
}

impl BackendRoute {
    pub fn new(control: PathBuf, destination: OsString) -> Self {
        Self {
            control,
            destination,
            forwards: Mutex::new(HashMap::new()),
        }
    }
    fn validate_master(&self) -> Result<(), HostKeyError> {
        let meta = std::fs::symlink_metadata(&self.control).map_err(|_| {
            fail("backend SSH master is unavailable; no direct connection was attempted")
        })?;
        if !self.control.is_absolute()
            || !meta.file_type().is_socket()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
        {
            return Err(fail(
                "backend SSH master socket is not private and owned by this client",
            ));
        }
        Ok(())
    }
    fn command(&self, operation: &str, specification: &str) -> Result<(), HostKeyError> {
        self.validate_master()?;
        let mut args = vec![
            "-F".into(),
            "/dev/null".into(),
            "-S".into(),
            self.control.as_os_str().into(),
            "-O".into(),
            operation.into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
        ];
        if operation != "check" {
            args.extend(["-L".into(), specification.into()]);
        }
        args.extend(["--".into(), self.destination.clone()]);
        let result = ProcessRunner.run_bounded(
            std::ffi::OsStr::new("ssh"),
            &args,
            Duration::from_secs(5),
        )?;
        if !result.success {
            return Err(fail(
                "backend SSH forwarding failed; no direct connection was attempted",
            ));
        }
        Ok(())
    }
    pub fn check_master(&self) -> Result<(), HostKeyError> {
        self.command("check", "")
    }
    pub fn endpoint(&self, host: &str, port: u16) -> Result<(String, u16), HostKeyError> {
        if host.is_empty()
            || port == 0
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_:%".contains(&b))
        {
            return Err(fail("invalid backend forwarding target"));
        }
        self.command("check", "")?;
        let mut forwards = self
            .forwards
            .lock()
            .map_err(|_| fail("backend forwarding registry is unavailable"))?;
        let key = (host.to_owned(), port);
        if let Some(forward) = forwards.get(&key) {
            return Ok(("127.0.0.1".into(), forward.port));
        }
        // Reserve an ephemeral port. The OpenSSH master owns the listener after
        // transfer; a collision fails closed instead of changing routing policy.
        let reservation = TcpListener::bind(("127.0.0.1", 0))?;
        let local_port = reservation.local_addr()?.port();
        let specification = format!("127.0.0.1:{local_port}:[{host}]:{port}");
        drop(reservation);
        self.command("forward", &specification)?;
        forwards.insert(
            key,
            Forward {
                port: local_port,
                specification,
            },
        );
        Ok(("127.0.0.1".into(), local_port))
    }
}
impl Drop for BackendRoute {
    fn drop(&mut self) {
        let specifications: Vec<_> = self
            .forwards
            .get_mut()
            .map(|m| m.values().map(|f| f.specification.clone()).collect())
            .unwrap_or_default();
        for specification in specifications {
            let _ = self.command("cancel", &specification);
        }
    }
}
fn fail(message: &str) -> HostKeyError {
    HostKeyError::Tool(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_master_refuses_forwarding_without_reconnect() {
        let route = BackendRoute::new(
            PathBuf::from("/no-such-client-owned-master.sock"),
            "backend.invalid".into(),
        );
        let error = route
            .endpoint("target.invalid", 22)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no direct connection was attempted"));
    }
    #[test]
    fn rejects_forwarding_option_injection() {
        let route = BackendRoute::new(PathBuf::from("/missing.sock"), "backend.invalid".into());
        for host in [
            "-oProxyCommand=bad",
            "host]evil",
            "host\nother",
            "host/path",
            "",
        ] {
            assert!(route
                .endpoint(host, 22)
                .unwrap_err()
                .to_string()
                .contains("invalid backend forwarding target"));
        }
    }
}
