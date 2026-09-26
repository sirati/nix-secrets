//! Edits text in the operator's terminal editor on this machine.
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;

/// `$VISUAL`, then `$EDITOR`, then `vi`.
pub fn command() -> String {
    ["VISUAL", "EDITOR"]
        .into_iter()
        .filter_map(std::env::var_os)
        .filter_map(|value| value.into_string().ok())
        .find(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "vi".into())
}

/// Writes `text` to a file in a new 0700 directory, runs `editor` on it, and
/// returns the result. The directory is removed afterwards. The editor runs
/// through `sh -c` so values like `code --wait` work, with the file as `$1`.
pub fn edit_with(editor: &str, text: &str) -> Result<String, String> {
    let directory = private_directory()
        .map_err(|error| format!("cannot create a temporary directory: {error}"))?;
    let result = run(editor, text, &directory);
    let _ = fs::remove_dir_all(&directory);
    result
}

fn run(editor: &str, text: &str, directory: &Path) -> Result<String, String> {
    let file = directory.join("COMMIT_EDITMSG");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)
        .and_then(|mut handle| handle.write_all(text.as_bytes()))
        .map_err(|error| format!("cannot write the message file: {error}"))?;
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("nix-secrets-editor")
        .arg(&file)
        .status()
        .map_err(|error| format!("cannot start {editor}: {error}"))?;
    if !status.success() {
        return Err(format!(
            "{editor} exited with {status}; the message is unchanged"
        ));
    }
    let edited = fs::read_to_string(&file)
        .map_err(|error| format!("cannot read the edited message: {error}"))?;
    Ok(edited.trim_end_matches('\n').to_owned())
}

fn private_directory() -> std::io::Result<std::path::PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let mut random = [0; 12];
    getrandom::fill(&mut random).map_err(std::io::Error::other)?;
    let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let directory = base.join(format!("nix-secrets-edit-{name}"));
    DirBuilder::new().mode(0o700).create(&directory)?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn edits_through_a_script_and_removes_the_file() {
        let scratch = tempfile::tempdir().unwrap();
        let script = scratch.path().join("fake-editor");
        let seen = scratch.path().join("seen");
        // Records the file's mode and its directory, then rewrites the message.
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nstat -c '%a' \"$(dirname \"$1\")\" > {seen}\ndirname \"$1\" >> {seen}\ncat \"$1\" >> {seen}\nprintf 'Edited subject\\n\\nbody\\n' > \"$1\"\n",
                seen = seen.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let edited = edit_with(&script.display().to_string(), "draft").unwrap();
        assert_eq!(edited, "Edited subject\n\nbody");
        let seen = fs::read_to_string(seen).unwrap();
        let mut lines = seen.lines();
        assert_eq!(lines.next(), Some("700"));
        let directory = lines.next().unwrap();
        assert_eq!(lines.next(), Some("draft"));
        assert!(!Path::new(directory).exists(), "the directory is removed");
    }

    #[test]
    fn a_failing_editor_reports_and_keeps_nothing() {
        assert!(edit_with("false", "draft").is_err());
    }
}
