use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::Path;
use std::process::Command;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: OsString,
    pub arguments: Vec<OsString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    NonUtf8RemoteArgument,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "remote command arguments must be valid UTF-8")
    }
}

impl std::error::Error for BuildError {}

impl CommandSpec {
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.arguments);
        command
    }
}

pub fn nix_eval(repository: &Path, attribute: &str) -> CommandSpec {
    CommandSpec {
        program: "nix".into(),
        arguments: vec![
            "eval".into(),
            "--json".into(),
            format!("{}#{attribute}", repository.display()).into(),
        ],
    }
}

pub fn backend(repository: &Path, socket: &Path) -> CommandSpec {
    CommandSpec {
        program: "nix".into(),
        arguments: vec![
            "run".into(),
            format!("{}#secrets-backend", repository.display()).into(),
            "--".into(),
            "--repository".into(),
            repository.as_os_str().into(),
            "--socket".into(),
            socket.as_os_str().into(),
        ],
    }
}

pub fn ssh(
    ssh_arguments: &[OsString],
    remote_arguments: &[OsString],
) -> Result<CommandSpec, BuildError> {
    let mut arguments = vec!["-o".into(), "StrictHostKeyChecking=yes".into()];
    arguments.extend_from_slice(ssh_arguments);
    arguments.push(quoted_remote_command(remote_arguments)?.into());
    Ok(CommandSpec {
        program: "ssh".into(),
        arguments,
    })
}

pub fn remote_backend(
    ssh_arguments: &[OsString],
    repository: &Path,
    local_socket: &Path,
    remote_socket: &Path,
) -> Result<CommandSpec, BuildError> {
    let local = backend(repository, remote_socket);
    let mut remote = vec![local.program];
    remote.extend(local.arguments);
    remote.push("--hold-channel".into());
    let mut forwarding = vec![
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-L".into(),
        format!("{}:{}", local_socket.display(), remote_socket.display()).into(),
    ];
    forwarding.extend_from_slice(ssh_arguments);
    ssh(&forwarding, &remote)
}

fn quoted_remote_command(arguments: &[OsString]) -> Result<String, BuildError> {
    arguments
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .map(|argument| format!("'{}'", argument.replace('\'', "'\\''")))
                .ok_or(BuildError::NonUtf8RemoteArgument)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|arguments| arguments.join(" "))
}

pub fn argv(spec: &CommandSpec) -> impl Iterator<Item = &OsStr> {
    std::iter::once(spec.program.as_os_str()).chain(spec.arguments.iter().map(OsString::as_os_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(spec: &CommandSpec) -> Vec<String> {
        argv(spec)
            .map(|part| part.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn evaluation_is_an_argv_without_shell_text() {
        assert_eq!(
            strings(&nix_eval(
                Path::new("/repo with spaces"),
                "nixSecretsSchemas"
            )),
            [
                "nix",
                "eval",
                "--json",
                "/repo with spaces#nixSecretsSchemas"
            ]
        );
    }

    #[test]
    fn local_backend_is_a_safe_nix_run_argv() {
        assert_eq!(
            strings(&backend(
                Path::new("/repo"),
                Path::new("/run/user/1/secrets.sock")
            )),
            [
                "nix",
                "run",
                "/repo#secrets-backend",
                "--",
                "--repository",
                "/repo",
                "--socket",
                "/run/user/1/secrets.sock"
            ]
        );
    }

    #[test]
    fn ssh_forces_strict_host_key_checking_and_keeps_default_known_hosts() {
        let args = vec![
            OsString::from("-p"),
            OsString::from("2222"),
            OsString::from("me@host"),
        ];
        let spec = remote_backend(
            &args,
            Path::new("/repo"),
            Path::new("/run/user/1/local"),
            Path::new("/run/user/1/remote"),
        )
        .unwrap();
        let actual = strings(&spec);
        assert_eq!(&actual[..3], ["ssh", "-o", "StrictHostKeyChecking=yes"]);
        assert!(actual.iter().all(|arg| !arg.contains("UserKnownHostsFile")));
        assert!(actual.last().unwrap().contains("'--hold-channel'"));
        assert!(actual
            .iter()
            .any(|part| part == "/run/user/1/local:/run/user/1/remote"));
        assert!(actual
            .windows(3)
            .any(|parts| parts == ["-p", "2222", "me@host"]));
    }

    #[test]
    fn remote_command_quotes_untrusted_paths() {
        let spec = remote_backend(
            &["host".into()],
            Path::new("/repo'; touch /tmp/pwned; '"),
            Path::new("/run/local"),
            Path::new("/run/socket"),
        )
        .unwrap();
        let actual = strings(&spec);
        assert!(actual
            .last()
            .unwrap()
            .contains("'\\''; touch /tmp/pwned; '\\''"));
    }
}
