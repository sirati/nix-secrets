//! Minimal sd_notify client: one datagram to `$NOTIFY_SOCKET`.

use std::ffi::OsStr;
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

pub fn socket_address(value: &OsStr) -> io::Result<SocketAddr> {
    match value.as_bytes() {
        [b'@', name @ ..] if !name.is_empty() => SocketAddr::from_abstract_name(name),
        [b'/', ..] => SocketAddr::from_pathname(value),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is neither absolute nor abstract",
        )),
    }
}

/// Sends `message` to the notify socket named by `socket` (the value of
/// `$NOTIFY_SOCKET`); `None` means the service manager is not listening.
pub fn send(socket: Option<&OsStr>, message: &str) -> io::Result<()> {
    let Some(socket) = socket else {
        return Ok(());
    };
    let address = socket_address(socket)?;
    let sender = UnixDatagram::unbound()?;
    let sent = sender.send_to_addr(message.as_bytes(), &address)?;
    if sent != message.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short notify datagram",
        ));
    }
    Ok(())
}

pub fn status_message(text: &str) -> String {
    let single_line: String = text
        .chars()
        .map(|character| if character == '\n' { ' ' } else { character })
        .collect();
    format!("STATUS={single_line}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::time::Duration;

    #[test]
    fn delivers_status_to_a_path_socket() {
        let dir =
            std::env::temp_dir().join(format!("waiter-notify-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        send(
            Some(path.as_os_str()),
            &status_message("still waiting for /a (3s)"),
        )
        .unwrap();
        let mut buffer = [0; 256];
        let length = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..length], b"STATUS=still waiting for /a (3s)");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn delivers_status_to_an_abstract_socket() {
        let name = format!("secrets-ready-waiter-test-{}", std::process::id());
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&address).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let env = std::ffi::OsString::from_vec(format!("@{name}").into_bytes());
        send(Some(&env), "STATUS=x").unwrap();
        let mut buffer = [0; 64];
        let length = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..length], b"STATUS=x");
    }

    #[test]
    fn absent_socket_is_a_no_op_and_relative_is_rejected() {
        send(None, "STATUS=x").unwrap();
        assert!(send(Some(OsStr::new("relative")), "STATUS=x").is_err());
        assert!(send(Some(OsStr::new("@")), "STATUS=x").is_err());
    }

    #[test]
    fn status_is_one_line() {
        assert_eq!(status_message("a\nb"), "STATUS=a b");
    }
}
