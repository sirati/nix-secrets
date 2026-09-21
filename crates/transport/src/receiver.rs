use crate::{Frame, FrameError, FrameKind};
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;

pub const DEPLOYER_SOCKET: &str = "/run/nix-secrets/deployer.sock";
pub const MANAGER_SOCKET: &str = "/run/nix-secrets/manager.sock";

#[derive(Debug)]
pub enum ReceiverError {
    Arguments(&'static str),
    Protocol(FrameError),
    Io(io::Error),
    Disabled,
}

impl fmt::Display for ReceiverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments(message) => f.write_str(message),
            Self::Protocol(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
            Self::Disabled => f.write_str("requested forwarding mode is disabled"),
        }
    }
}
impl std::error::Error for ReceiverError {}
impl From<io::Error> for ReceiverError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<FrameError> for ReceiverError {
    fn from(value: FrameError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Default)]
struct AllowedSockets {
    manager: Option<PathBuf>,
    deployer: Option<PathBuf>,
}

pub fn login_shell_arguments(
    arguments: Vec<OsString>,
    original_command: Option<&OsString>,
) -> Result<Vec<OsString>, ReceiverError> {
    if arguments.first().is_some_and(|value| value == "-c") {
        if original_command.is_some_and(|value| !value.is_empty()) {
            return Err(ReceiverError::Arguments("remote commands are forbidden"));
        }
        return match arguments.as_slice() {
            [flag, token] if flag == "-c" && token == "nix-secrets-forward-deployer" => {
                Ok(vec!["--deployer-socket".into(), DEPLOYER_SOCKET.into()])
            }
            [flag, token] if flag == "-c" && token == "nix-secrets-forward-manager" => {
                Ok(vec!["--manager-socket".into(), MANAGER_SOCKET.into()])
            }
            _ => Err(ReceiverError::Arguments("invalid forced-command token")),
        };
    }
    Ok(arguments)
}

pub fn run_receiver<I, R, W>(arguments: I, mut input: R, output: W) -> Result<(), ReceiverError>
where
    I: IntoIterator<Item = OsString>,
    R: Read,
    W: Write + Send,
{
    let allowed = parse_arguments(arguments)?;
    let open = Frame::read_from(&mut input)?;
    if !open.payload.is_empty() {
        return Err(ReceiverError::Arguments("open frame payload must be empty"));
    }
    let path = match open.kind {
        FrameKind::OpenManager => allowed.manager.as_deref(),
        FrameKind::OpenDeployer => allowed.deployer.as_deref(),
        _ => {
            return Err(ReceiverError::Arguments(
                "first frame must select a forwarding mode",
            ));
        }
    }
    .ok_or(ReceiverError::Disabled)?;
    let stream = UnixStream::connect(path)?;
    relay_connected(&mut input, output, stream)
}

fn relay_connected(
    input: &mut impl Read,
    mut output: impl Write + Send,
    stream: UnixStream,
) -> Result<(), ReceiverError> {
    let response_stream = stream.try_clone()?;
    let shutdown_stream = stream.try_clone()?;
    relay_streams(input, &mut output, stream, response_stream, move || {
        shutdown_stream.shutdown(Shutdown::Write)
    })
}

fn relay_streams(
    input: &mut impl Read,
    mut output: impl Write + Send,
    mut request_stream: impl Write,
    mut response_stream: impl Read + Send,
    close_request: impl FnOnce() -> io::Result<()>,
) -> Result<(), ReceiverError> {
    Frame {
        kind: FrameKind::Data,
        payload: Vec::new(),
    }
    .write_to(&mut output)?;
    thread::scope(|scope| -> Result<(), ReceiverError> {
        let response = scope.spawn(move || -> Result<(), ReceiverError> {
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let count = response_stream.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                Frame {
                    kind: FrameKind::Data,
                    payload: buffer[..count].to_vec(),
                }
                .write_to(&mut output)?;
            }
            Frame {
                kind: FrameKind::Close,
                payload: Vec::new(),
            }
            .write_to(&mut output)?;
            Ok(())
        });
        loop {
            let frame = Frame::read_from(input)?;
            match frame.kind {
                FrameKind::Data => request_stream.write_all(&frame.payload)?,
                FrameKind::Close if frame.payload.is_empty() => break,
                _ => return Err(ReceiverError::Arguments("invalid relay frame")),
            }
        }
        close_request()?;
        response
            .join()
            .map_err(|_| ReceiverError::Io(io::Error::other("relay thread panicked")))??;
        Ok(())
    })
}

fn parse_arguments<I>(arguments: I) -> Result<AllowedSockets, ReceiverError>
where
    I: IntoIterator<Item = OsString>,
{
    let values: Vec<OsString> = arguments.into_iter().collect();
    let mut allowed = AllowedSockets::default();
    let mut index = 0;
    while index < values.len() {
        let target = match values[index].to_str() {
            Some("--manager-socket") => &mut allowed.manager,
            Some("--deployer-socket") => &mut allowed.deployer,
            _ => return Err(ReceiverError::Arguments("unknown receiver argument")),
        };
        index += 1;
        let path = values
            .get(index)
            .ok_or(ReceiverError::Arguments("socket option requires a path"))?;
        let path = PathBuf::from(path);
        validate_socket_path(&path)?;
        if target.replace(path).is_some() {
            return Err(ReceiverError::Arguments("duplicate socket option"));
        }
        index += 1;
    }
    if allowed.manager.is_none() && allowed.deployer.is_none() {
        return Err(ReceiverError::Arguments(
            "at least one forwarding mode must be enabled",
        ));
    }
    Ok(allowed)
}

fn validate_socket_path(path: &Path) -> Result<(), ReceiverError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        Err(ReceiverError::Arguments(
            "socket path must be absolute and normalized",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_relays_binary_bytes_without_interpreting_them() {
        let mut request = Vec::new();
        Frame {
            kind: FrameKind::Data,
            payload: vec![0, 255, 7],
        }
        .write_to(&mut request)
        .unwrap();
        Frame {
            kind: FrameKind::Close,
            payload: vec![],
        }
        .write_to(&mut request)
        .unwrap();
        let mut response = Vec::new();
        let mut service_request = Vec::new();
        relay_streams(
            &mut request.as_slice(),
            &mut response,
            &mut service_request,
            &[9, 0, 8][..],
            || Ok(()),
        )
        .unwrap();
        assert_eq!(service_request, [0, 255, 7]);
        let mut cursor = response.as_slice();
        assert_eq!(
            Frame::read_from(&mut cursor).unwrap().payload,
            Vec::<u8>::new()
        );
        assert_eq!(Frame::read_from(&mut cursor).unwrap().payload, [9, 0, 8]);
        assert_eq!(
            Frame::read_from(&mut cursor).unwrap().kind,
            FrameKind::Close
        );
    }

    #[test]
    fn socket_selection_cannot_supply_a_path_over_the_wire() {
        let mut request = Vec::new();
        Frame {
            kind: FrameKind::OpenDeployer,
            payload: b"/tmp/attacker".to_vec(),
        }
        .write_to(&mut request)
        .unwrap();
        let result = run_receiver(
            ["--deployer-socket".into(), "/run/allowed.sock".into()],
            request.as_slice(),
            Vec::new(),
        );
        assert!(matches!(result, Err(ReceiverError::Arguments(_))));
    }

    #[test]
    fn login_shell_accepts_only_exact_forced_tokens() {
        assert_eq!(
            login_shell_arguments(
                vec!["-c".into(), "nix-secrets-forward-deployer".into()],
                None
            )
            .unwrap(),
            vec![
                OsString::from("--deployer-socket"),
                OsString::from(DEPLOYER_SOCKET)
            ]
        );
        for invalid in [
            vec!["-c".into(), "nix-secrets-forward-deployer extra".into()],
            vec!["-c".into(), "sh".into()],
            vec![
                "-c".into(),
                "nix-secrets-forward-deployer".into(),
                "extra".into(),
            ],
        ] {
            assert!(login_shell_arguments(invalid, None).is_err());
        }
        assert!(login_shell_arguments(
            vec!["-c".into(), "nix-secrets-forward-deployer".into()],
            Some(&"requested-command".into())
        )
        .is_err());
    }
}
