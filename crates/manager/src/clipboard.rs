use std::io::Write;
use std::process::{Command, Stdio};

pub fn copy(value: &[u8]) -> Result<(), String> {
    let mut child = Command::new("wl-copy")
        .args(["--type", "text/plain;charset=utf-8"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start wl-copy: {error}"))?;
    let mut stdin = child.stdin.take().ok_or("wl-copy stdin is unavailable")?;
    stdin
        .write_all(value)
        .map_err(|error| format!("cannot send value to wl-copy: {error}"))?;
    drop(stdin);
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for wl-copy: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("wl-copy rejected the generated value".into())
    }
}
