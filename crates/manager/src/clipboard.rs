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

const PASTE_LIMIT: u64 = 1024 * 1024;
const PASTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Reads the local clipboard, or the primary selection for a middle click,
/// with the first available tool. One trailing newline is removed. The
/// content is never logged or put into an error message.
pub fn paste(primary: bool) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let x11 = std::env::var_os("DISPLAY").is_some();
    let mut candidates: Vec<(&str, Vec<&str>)> = Vec::new();
    if wayland {
        let mut arguments = vec!["--no-newline", "--type", "text"];
        if primary {
            arguments.push("--primary");
        }
        candidates.push(("wl-paste", arguments));
    }
    if x11 {
        let selection = if primary { "primary" } else { "clipboard" };
        candidates.push(("xclip", vec!["-selection", selection, "-o"]));
        candidates.push((
            "xsel",
            vec![
                if primary { "--primary" } else { "--clipboard" },
                "--output",
            ],
        ));
    }
    if !primary {
        candidates.push(("pbpaste", vec![]));
    }
    let mut failures = Vec::new();
    for (program, arguments) in candidates {
        match read_tool(program, &arguments) {
            Ok(mut value) => {
                if value.last() == Some(&b'\n') {
                    value.pop();
                }
                return Ok(value);
            }
            Err(None) => {}
            Err(Some(failure)) => failures.push(format!("{program}: {failure}")),
        }
    }
    if failures.is_empty() {
        Err("cannot read the clipboard: install wl-clipboard (Wayland), xclip or xsel (X11)".into())
    } else {
        Err(format!(
            "cannot read the clipboard ({})",
            failures.join("; ")
        ))
    }
}

/// `Err(None)` when the tool is not installed.
fn read_tool(
    program: &str,
    arguments: &[&str],
) -> Result<zeroize::Zeroizing<Vec<u8>>, Option<String>> {
    use std::io::Read;
    let mut child = match Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(None),
        Err(error) => return Err(Some(error.to_string())),
    };
    let mut stdout = child.stdout.take().ok_or(Some("no output pipe".into()))?;
    let reader = std::thread::spawn(move || {
        let mut value = zeroize::Zeroizing::new(Vec::new());
        let result = stdout
            .by_ref()
            .take(PASTE_LIMIT + 1)
            .read_to_end(&mut value);
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        result.map(|_| value)
    });
    let deadline = std::time::Instant::now() + PASTE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Some("timed out".into()));
            }
        }
    };
    let value = reader
        .join()
        .map_err(|_| Some("reader failed".to_owned()))?
        .map_err(|error| Some(error.to_string()))?;
    if !status.success() {
        // wl-paste exits 1 with "No selection" when the clipboard is empty.
        return Err(Some("the clipboard is empty or holds no text".into()));
    }
    if value.len() as u64 > PASTE_LIMIT {
        return Err(Some("the clipboard content exceeds 1 MiB".into()));
    }
    Ok(value)
}
