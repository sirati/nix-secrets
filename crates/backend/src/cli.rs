use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Arguments {
    pub repository: PathBuf,
    pub socket: PathBuf,
    pub manifest: Option<PathBuf>,
    pub hold_channel: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    MissingValue(&'static str),
    MissingRequired(&'static str),
    Duplicate(&'static str),
    Unknown(OsString),
    SocketNotAbsolute,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue(option) => write!(formatter, "{option} requires a value"),
            Self::MissingRequired(option) => write!(formatter, "missing required {option}"),
            Self::Duplicate(option) => write!(formatter, "{option} was provided more than once"),
            Self::Unknown(value) => write!(formatter, "unknown argument {:?}", value),
            Self::SocketNotAbsolute => write!(formatter, "--socket must be an absolute path"),
        }
    }
}

impl std::error::Error for ParseError {}

impl Arguments {
    pub fn parse(input: impl IntoIterator<Item = OsString>) -> Result<Self, ParseError> {
        let mut input = input.into_iter();
        let mut repository = None;
        let mut socket = None;
        let mut manifest = None;
        let mut hold_channel = false;
        while let Some(option) = input.next() {
            if option == "--hold-channel" {
                if hold_channel {
                    return Err(ParseError::Duplicate("--hold-channel"));
                }
                hold_channel = true;
                continue;
            }
            let (name, slot) = match option.to_str() {
                Some("--repository") => ("--repository", &mut repository),
                Some("--socket") => ("--socket", &mut socket),
                Some("--manifest") => ("--manifest", &mut manifest),
                _ => return Err(ParseError::Unknown(option)),
            };
            if slot.is_some() {
                return Err(ParseError::Duplicate(name));
            }
            *slot = Some(PathBuf::from(
                input.next().ok_or(ParseError::MissingValue(name))?,
            ));
        }
        let repository = repository.ok_or(ParseError::MissingRequired("--repository"))?;
        let socket = socket.ok_or(ParseError::MissingRequired("--socket"))?;
        if !socket.is_absolute() {
            return Err(ParseError::SocketNotAbsolute);
        }
        Ok(Self {
            repository,
            socket,
            manifest,
            hold_channel,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn accepts_only_fixed_named_arguments() {
        let parsed = Arguments::parse(args(&[
            "--repository",
            "/repo",
            "--socket",
            "/run/user/1/backend.sock",
            "--manifest",
            "/nix/store/manifest.json",
        ]))
        .unwrap();
        assert_eq!(parsed.repository, PathBuf::from("/repo"));
        assert_eq!(
            parsed.manifest,
            Some(PathBuf::from("/nix/store/manifest.json"))
        );
        assert!(!parsed.hold_channel);
        assert!(
            Arguments::parse(args(&[
                "--repository",
                "/repo",
                "--socket",
                "/run/backend.sock",
                "--hold-channel",
            ]))
            .unwrap()
            .hold_channel
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_relative_socket_arguments() {
        assert!(matches!(
            Arguments::parse(args(&["--repository", "/r", "--socket", "relative"])),
            Err(ParseError::SocketNotAbsolute)
        ));
        assert!(matches!(
            Arguments::parse(args(&[
                "--repository",
                "/r",
                "--repository",
                "/x",
                "--socket",
                "/s"
            ])),
            Err(ParseError::Duplicate("--repository"))
        ));
        assert!(matches!(
            Arguments::parse(args(&["--repository", "/r", "--socket", "/s", "--evil"])),
            Err(ParseError::Unknown(_))
        ));
    }
}
