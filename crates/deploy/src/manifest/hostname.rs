use crate::DeployError;
use std::fs;

pub fn system_hostname() -> Result<String, DeployError> {
    let value = fs::read_to_string("/proc/sys/kernel/hostname")?;
    let hostname = value.trim().to_owned();
    if hostname.is_empty() {
        Err(DeployError::Invalid("system hostname is empty".into()))
    } else {
        Ok(hostname)
    }
}
