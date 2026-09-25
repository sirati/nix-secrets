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

const PASTE_LIMIT: usize = 1024 * 1024;

/// Reads the clipboard for an explicit Ctrl+V. This is the only call site:
/// nothing polls, prefetches or retries.
///
/// It reads the X11 CLIPBOARD selection in-process through arboard, over
/// Xwayland under a Wayland session. arboard creates one 1x1 helper window
/// and never maps it, so no window appears and the window manager is not
/// involved. `wl-paste` is deliberately not used: on compositors without a
/// data-control protocol, such as GNOME's Mutter, it maps a focus surface
/// for every read, which makes the window manager retile. One trailing
/// newline is removed. The content is never logged or put in an error.
pub fn paste() -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    if std::env::var_os("DISPLAY").is_none() {
        return Err(
            "direct clipboard reading needs X11 or Xwayland (DISPLAY is unset); \
             use the terminal's paste instead"
                .into(),
        );
    }
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|error| format!("cannot open the X11 clipboard: {error}"))?;
    let text = clipboard.get_text().map_err(|error| match error {
        arboard::Error::ContentNotAvailable => "the clipboard is empty or holds no text".into(),
        other => format!("cannot read the clipboard: {other}"),
    })?;
    let mut value = zeroize::Zeroizing::new(text.into_bytes());
    if value.len() > PASTE_LIMIT {
        return Err("the clipboard content exceeds 1 MiB".into());
    }
    if value.last() == Some(&b'\n') {
        value.pop();
    }
    Ok(value)
}
