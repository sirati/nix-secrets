use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};

pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: u64 = 16 * 1024;

pub fn load_manifest(path: &Path) -> io::Result<String> {
    read_bounded(File::open(path)?)
}

pub fn evaluate_manifest(repository: &Path) -> io::Result<String> {
    let reference = flake_reference(repository)?;
    let mut child = Command::new("nix")
        .args(["eval", "--json", "--no-write-lock-file"])
        .arg(reference)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // The persistent backend may have been started from an active TUI.
        // Child warnings must never write to that terminal behind ratatui.
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing nix stderr"))?;
    let diagnostics = std::thread::spawn(move || {
        let mut captured = Vec::new();
        let read = stderr
            .by_ref()
            .take(MAX_DIAGNOSTIC_BYTES + 1)
            .read_to_end(&mut captured);
        // Continue draining after the bound so a noisy child cannot deadlock
        // while its manifest is read on the other pipe.
        let _ = io::copy(&mut stderr, &mut io::sink());
        read?;
        let truncated = captured.len() as u64 > MAX_DIAGNOSTIC_BYTES;
        captured.truncate(MAX_DIAGNOSTIC_BYTES as usize);
        let mut text = String::from_utf8_lossy(&captured).trim().to_owned();
        if truncated {
            text.push_str("\n[diagnostics truncated]");
        }
        Ok::<_, io::Error>(text)
    });
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing nix stdout"))?;
    let output = match read_bounded(stdout) {
        Ok(output) => output,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = diagnostics.join();
            return Err(error);
        }
    };
    let status = child.wait()?;
    let diagnostics = diagnostics
        .join()
        .map_err(|_| io::Error::other("Nix diagnostic reader failed"))??;
    if !status.success() {
        return Err(io::Error::other(format!(
            "nix eval failed with {status}{}",
            if diagnostics.is_empty() {
                String::new()
            } else {
                format!(":\n{diagnostics}")
            }
        )));
    }
    Ok(output)
}

fn flake_reference(repository: &Path) -> io::Result<OsString> {
    let Some(repository) = repository.to_str() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "repository path is not valid UTF-8",
        ));
    };
    Ok(format!("{repository}#nixSecretsSchemas").into())
}

fn read_bounded(mut reader: impl Read) -> io::Result<String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "evaluated manifest exceeds the size limit",
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_manifest_input() {
        let input = vec![b'x'; (MAX_MANIFEST_BYTES + 1) as usize];
        assert_eq!(
            read_bounded(&input[..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn constructs_only_the_canonical_output_reference() {
        assert_eq!(
            flake_reference(Path::new("/repo with spaces")).unwrap(),
            OsString::from("/repo with spaces#nixSecretsSchemas")
        );
    }
}
