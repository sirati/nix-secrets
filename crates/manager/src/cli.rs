use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub ssh_args: Vec<OsString>,
    pub repository: PathBuf,
    pub identity: Option<PathBuf>,
    /// Reuse the 1Password CLI session of the calling terminal (10 minutes)
    /// instead of authorizing each decryption separately.
    pub shared_session: bool,
}

impl Invocation {
    pub fn is_local(&self) -> bool {
        self.ssh_args.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    MissingDelimiter,
    MissingRepository,
    TooManyRepositoryArguments,
    MissingIdentity,
    DuplicateIdentity,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDelimiter => write!(f, "missing required `--` delimiter"),
            Self::MissingRepository => write!(f, "missing repository after `--`"),
            Self::TooManyRepositoryArguments => {
                write!(f, "exactly one repository must follow `--`")
            }
            Self::MissingIdentity => write!(f, "--secret-identity requires a path"),
            Self::DuplicateIdentity => write!(f, "--secret-identity was provided more than once"),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse<I>(arguments: I, home: &Path) -> Result<Invocation, ParseError>
where
    I: IntoIterator<Item = OsString>,
{
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let Some(delimiter) = arguments.iter().position(|arg| arg == "--") else {
        return Err(ParseError::MissingDelimiter);
    };
    let repository_arguments = &arguments[delimiter + 1..];
    let repository = match repository_arguments {
        [] => return Err(ParseError::MissingRepository),
        [repository] => repository,
        _ => return Err(ParseError::TooManyRepositoryArguments),
    };

    let mut ssh_args = Vec::new();
    let mut identity = None;
    let mut shared_session = false;
    let mut before = arguments[..delimiter].iter();
    while let Some(argument) = before.next() {
        if argument == "--secret-identity" {
            if identity.is_some() {
                return Err(ParseError::DuplicateIdentity);
            }
            identity = Some(PathBuf::from(
                before.next().ok_or(ParseError::MissingIdentity)?,
            ));
        } else if argument == "--1password-shared-session" {
            shared_session = true;
        } else {
            ssh_args.push(argument.clone());
        }
    }
    let repository = if ssh_args.is_empty() {
        expand_home(repository, home)
    } else {
        PathBuf::from(repository)
    };
    Ok(Invocation {
        ssh_args,
        repository,
        identity,
        shared_session,
    })
}

pub fn expand_home(path: &OsStr, home: &Path) -> PathBuf {
    let path = Path::new(path);
    if path == Path::new("~") {
        return home.to_owned();
    }
    match path.strip_prefix("~/") {
        Ok(relative) => home.join(relative),
        Err(_) => path.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn local_requires_an_explicit_delimiter() {
        let parsed = parse(os(&["--", "~/repo"]), Path::new("/home/me")).unwrap();
        assert!(parsed.is_local());
        assert_eq!(parsed.repository, Path::new("/home/me/repo"));
        assert_eq!(parsed.identity, None);
        assert_eq!(
            parse(os(&["~/repo"]), Path::new("/home/me")),
            Err(ParseError::MissingDelimiter)
        );
    }

    #[test]
    fn extracts_runtime_only_decryption_identity() {
        let parsed = parse(
            os(&["--secret-identity", "/run/key", "host", "--", "/repo"]),
            Path::new("/h"),
        )
        .unwrap();
        assert_eq!(parsed.identity, Some(PathBuf::from("/run/key")));
        assert_eq!(parsed.ssh_args, os(&["host"]));
    }

    #[test]
    fn one_password_session_scope_is_per_decryption_unless_shared() {
        let default = parse(os(&["--", "/repo"]), Path::new("/h")).unwrap();
        assert!(!default.shared_session);
        let shared = parse(
            os(&["--1password-shared-session", "host", "--", "/repo"]),
            Path::new("/h"),
        )
        .unwrap();
        assert!(shared.shared_session);
        assert_eq!(shared.ssh_args, os(&["host"]));
    }

    #[test]
    fn preserves_ssh_arguments() {
        let parsed = parse(
            os(&["-p", "2222", "user@example", "--", "/srv/config"]),
            Path::new("/home/me"),
        )
        .unwrap();
        assert_eq!(parsed.ssh_args, os(&["-p", "2222", "user@example"]));
        assert_eq!(parsed.repository, Path::new("/srv/config"));
    }

    #[test]
    fn leaves_remote_home_expansion_to_the_backend() {
        let parsed = parse(os(&["host", "--", "~/repo"]), Path::new("/local/home")).unwrap();
        assert_eq!(parsed.repository, Path::new("~/repo"));
    }

    #[test]
    fn rejects_missing_or_ambiguous_repository() {
        assert_eq!(
            parse(os(&["--"]), Path::new("/h")),
            Err(ParseError::MissingRepository)
        );
        assert_eq!(
            parse(os(&["--", "a", "b"]), Path::new("/h")),
            Err(ParseError::TooManyRepositoryArguments)
        );
        assert_eq!(
            parse(os(&["host", "--", "a", "--"]), Path::new("/h")),
            Err(ParseError::TooManyRepositoryArguments)
        );
    }

    #[test]
    fn only_expands_a_home_path_component() {
        assert_eq!(
            expand_home(OsStr::new("~"), Path::new("/h")),
            Path::new("/h")
        );
        assert_eq!(
            expand_home(OsStr::new("~/a"), Path::new("/h")),
            Path::new("/h/a")
        );
        assert_eq!(
            expand_home(OsStr::new("~other/a"), Path::new("/h")),
            Path::new("~other/a")
        );
    }
}
