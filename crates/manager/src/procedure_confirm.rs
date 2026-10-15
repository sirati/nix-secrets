//! `nix-secrets procedure-confirm`: inside a procedure, asks the operator
//! to confirm a risky step and waits for the answer.
//!
//! ```text
//! nix-secrets procedure-confirm [--repository PATH] [--backend-socket PATH] --label TEXT --reason TEXT [--item TEXT]...
//! ```
//!
//! The TUI shows a red warning dialog with the label, the reason and the
//! items, such as the dirty files of a git tree. Only typing `yes` and
//! Enter confirms; `n` or Esc declines. Nothing confirms on its own: no
//! profile, approval or countdown. It exits 0 only when the operator confirmed, and 1 when they
//! declined, outside a procedure, without a backend or an attached TUI, or
//! on any error. The procedure lists the answer as a step: a confirmation
//! as a warning, a refusal as a denied step.
use crate::procedure_command::connect_running;
use crate::with_secrets::Options;
use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::procedure::{clean_text, PROCEDURE_ENVIRONMENT};
use nix_secrets_core::{Request, Response};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "usage: nix-secrets procedure-confirm [--repository PATH] \
[--backend-socket PATH] --label TEXT --reason TEXT [--item TEXT]...";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmRequest {
    pub options: Options,
    pub label: String,
    pub reason: String,
    pub items: Vec<String>,
}

pub fn parse(
    arguments: impl IntoIterator<Item = OsString>,
    working_directory: PathBuf,
) -> Result<ConfirmRequest, String> {
    let mut arguments = arguments.into_iter();
    let mut options = Options {
        repository: working_directory,
        ..Options::default()
    };
    let (mut label, mut reason, mut items) = (None, None, Vec::new());
    while let Some(argument) = arguments.next() {
        let name = argument
            .to_str()
            .ok_or_else(|| format!("unexpected argument {argument:?}; {USAGE}"))?
            .to_owned();
        let mut value = |name: &str| {
            arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(|| format!("{name} requires UTF-8 text; {USAGE}"))
        };
        match name.as_str() {
            "--label" => label = Some(value("--label")?),
            "--reason" => reason = Some(value("--reason")?),
            "--item" => items.push(value("--item")?),
            "--repository" => options.repository = value("--repository")?.into(),
            "--backend-socket" => options.backend_socket = Some(value("--backend-socket")?.into()),
            _ => return Err(format!("unexpected argument {name:?}; {USAGE}")),
        }
    }
    let label = label
        .filter(|label| !label.trim().is_empty())
        .ok_or_else(|| format!("name the step with --label; {USAGE}"))?;
    let reason = reason
        .filter(|reason| !reason.trim().is_empty())
        .ok_or_else(|| format!("give the reason with --reason; {USAGE}"))?;
    Ok(ConfirmRequest {
        options,
        label,
        reason,
        items,
    })
}

/// Asks and waits, however long the operator takes. `Ok(confirmed)` is the
/// operator's answer; `Err` is why nobody could answer.
fn ask(request: &ConfirmRequest, runtime: &Path, procedure: String) -> Result<bool, String> {
    let mut stream = connect_running(&request.options, runtime)?;
    write_json(
        &mut stream,
        &Request::ConfirmProcedureStep {
            procedure,
            label: request.label.clone(),
            reason: request.reason.clone(),
            items: request.items.clone(),
        },
    )
    .map_err(|error| error.to_string())?;
    match read_json::<Response>(&mut stream).map_err(|error| error.to_string())? {
        Some(Response::ProcedureConfirmation { confirmed }) => Ok(confirmed),
        Some(Response::Error { message }) => Err(message),
        Some(other) => Err(format!("unexpected backend response: {other:?}")),
        None => Err("the backend closed the connection without an answer".into()),
    }
}

/// Runs the command: 0 only when the operator confirmed, 1 otherwise. What
/// is asked and the answer are printed to `stderr`.
pub fn confirm(
    request: &ConfirmRequest,
    runtime: &Path,
    token: Option<String>,
    stderr: &mut dyn Write,
) -> i32 {
    let label = clean_text(&request.label, usize::MAX);
    let Some(token) = token else {
        let _ = writeln!(
            stderr,
            "nix-secrets: not confirmed: {label}: not inside `nix-secrets procedure` \
             ({PROCEDURE_ENVIRONMENT} is unset), so nobody can be asked"
        );
        return 1;
    };
    let _ = writeln!(
        stderr,
        "nix-secrets: waiting for the operator to confirm: {label}: {}",
        clean_text(&request.reason, usize::MAX)
    );
    match ask(request, runtime, token) {
        Ok(true) => {
            let _ = writeln!(stderr, "nix-secrets: the operator confirmed: {label}");
            0
        }
        Ok(false) => {
            let _ = writeln!(stderr, "nix-secrets: the operator declined: {label}");
            1
        }
        Err(error) => {
            let _ = writeln!(stderr, "nix-secrets: not confirmed: {label}: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_label_reason_and_repeated_items() {
        let parsed = parse(
            os(&[
                "--label",
                "deployed from a dirty tree",
                "--item",
                "M flake.nix",
                "--reason",
                "uncommitted changes",
                "--item",
                "?? new.nix",
                "--backend-socket",
                "/b.sock",
            ]),
            "/cwd".into(),
        )
        .unwrap();
        assert_eq!(parsed.label, "deployed from a dirty tree");
        assert_eq!(parsed.reason, "uncommitted changes");
        assert_eq!(parsed.items, ["M flake.nix", "?? new.nix"]);
        assert_eq!(parsed.options.repository, PathBuf::from("/cwd"));
        assert_eq!(
            parsed.options.backend_socket,
            Some(PathBuf::from("/b.sock"))
        );
        let bare = parse(os(&["--label", "l", "--reason", "r"]), "/cwd".into()).unwrap();
        assert!(bare.items.is_empty());
        for wrong in [
            &["--reason", "r"][..],
            &["--label", "l"],
            &["--label", " ", "--reason", "r"],
            &["--label", "l", "--reason", "r", "--item"],
            &["--label", "l", "--reason", "r", "--yes"],
        ] {
            assert!(parse(os(wrong), "/cwd".into()).is_err(), "{wrong:?}");
        }
    }

    fn request(socket: PathBuf) -> ConfirmRequest {
        ConfirmRequest {
            options: Options {
                backend_socket: Some(socket),
                ..Options::default()
            },
            label: "deployed from a dirty tree".into(),
            reason: "uncommitted changes".into(),
            items: vec!["M flake.nix".into()],
        }
    }

    /// Runs the command against a backend that answers `response`.
    fn against(response: Option<Response>) -> (i32, String, Option<Request>) {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("backend.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let backend = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let asked = read_json::<Request>(&mut connection).unwrap();
            if let Some(response) = response {
                write_json(&mut connection, &response).unwrap();
            }
            asked
        });
        let mut stderr = Vec::new();
        let code = confirm(
            &request(socket),
            temp.path(),
            Some("proc-1-ab:secret".into()),
            &mut stderr,
        );
        let asked = backend.join().unwrap();
        (code, String::from_utf8(stderr).unwrap(), asked)
    }

    #[test]
    fn exits_zero_only_when_the_operator_confirmed() {
        let (code, stderr, asked) =
            against(Some(Response::ProcedureConfirmation { confirmed: true }));
        assert_eq!(code, 0, "{stderr}");
        assert!(stderr.contains("the operator confirmed: deployed from a dirty tree"));
        match asked {
            Some(Request::ConfirmProcedureStep {
                procedure,
                label,
                items,
                ..
            }) => {
                assert_eq!(procedure, "proc-1-ab:secret");
                assert_eq!(label, "deployed from a dirty tree");
                assert_eq!(items, ["M flake.nix"]);
            }
            other => panic!("unexpected {other:?}"),
        }
        let (code, stderr, _) = against(Some(Response::ProcedureConfirmation { confirmed: false }));
        assert_eq!(code, 1);
        assert!(stderr.contains("the operator declined"), "{stderr}");
        let (code, stderr, _) = against(Some(Response::Error {
            message: "no nix-secrets TUI is attached".into(),
        }));
        assert_eq!(code, 1);
        assert!(stderr.contains("not confirmed") && stderr.contains("no nix-secrets TUI"));
        // A success meant for another request is no confirmation.
        assert_eq!(against(Some(Response::Success)).0, 1);
        assert_eq!(against(None).0, 1);
    }

    #[test]
    fn without_a_procedure_or_a_backend_nothing_is_confirmed() {
        let temp = tempfile::tempdir().unwrap();
        let request = request(temp.path().join("missing.sock"));
        let mut stderr = Vec::new();
        assert_eq!(confirm(&request, temp.path(), None, &mut stderr), 1);
        assert!(String::from_utf8_lossy(&stderr).contains("NIX_SECRETS_PROCEDURE is unset"));
        let mut stderr = Vec::new();
        assert_eq!(
            confirm(&request, temp.path(), Some("p:s".into()), &mut stderr),
            1
        );
        assert!(String::from_utf8_lossy(&stderr).contains("missing.sock"));
    }
}
