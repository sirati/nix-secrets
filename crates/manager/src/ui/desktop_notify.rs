//! Desktop notifications through `org.freedesktop.Notifications` on the
//! session bus, for terminals that turn no escape sequence into one, such
//! as GNOME Console and GNOME Terminal with upstream VTE.
//!
//! The TUI talks to the bus itself: a minimal D-Bus client (EXTERNAL
//! authentication, `Hello`, `Notify`, `CloseNotification`) on its own
//! thread, so a slow or missing notification daemon never stalls the UI. It
//! is used only in a local graphical session, never over SSH, where a bus
//! found in the environment would belong to the remote host.
//!
//! A notification replaces the previous one of the same request, so a
//! reminder does not stack on its announcement, and closes once the
//! request is answered or gone.
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

/// How long one bus operation may take before the connection is dropped.
const BUS_TIMEOUT: Duration = Duration::from_secs(2);
/// The largest message read from the bus.
const MAX_MESSAGE: usize = 1 << 20;

/// What the TUI asks of the notification daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DesktopCall {
    /// Shows a notification for `key`, replacing its previous one.
    Notify {
        key: String,
        summary: String,
        body: String,
    },
    /// Takes the notification for `key` away, if one is shown.
    Close { key: String },
}

/// Where the session bus listens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BusAddress {
    Path(PathBuf),
    Abstract(Vec<u8>),
}

/// The session bus of a local graphical session, if the TUI runs in one:
/// no SSH connection, a Wayland or X11 display, and a bus address.
pub(crate) fn local_session_bus(env: &dyn Fn(&str) -> Option<String>) -> Option<BusAddress> {
    let set = |name: &str| env(name).is_some_and(|value| !value.is_empty());
    if set("SSH_CONNECTION") || set("SSH_CLIENT") || set("SSH_TTY") {
        return None;
    }
    if !set("WAYLAND_DISPLAY") && !set("DISPLAY") {
        return None;
    }
    match env("DBUS_SESSION_BUS_ADDRESS").filter(|value| !value.is_empty()) {
        Some(address) => parse_address(&address),
        None => {
            let runtime = env("XDG_RUNTIME_DIR").filter(|value| !value.is_empty())?;
            let path = PathBuf::from(runtime).join("bus");
            path.exists().then_some(BusAddress::Path(path))
        }
    }
}

/// The first `unix:path=` or `unix:abstract=` address of a D-Bus address
/// list.
pub(crate) fn parse_address(addresses: &str) -> Option<BusAddress> {
    addresses.split(';').find_map(|address| {
        let options = address.strip_prefix("unix:")?;
        options.split(',').find_map(|option| {
            let (key, value) = option.split_once('=')?;
            let value = unescape(value)?;
            match key {
                "path" => Some(BusAddress::Path(PathBuf::from(
                    String::from_utf8(value).ok()?,
                ))),
                "abstract" => Some(BusAddress::Abstract(value)),
                _ => None,
            }
        })
    })
}

/// Undoes the `%xx` escaping of D-Bus address values.
fn unescape(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Some(out)
}

/// Sends [`DesktopCall`]s from a thread of its own.
pub(crate) struct Desktop {
    calls: mpsc::Sender<DesktopCall>,
}

impl Desktop {
    /// `desktop_entry` names the terminal's desktop file, so the desktop
    /// shows the notification as the terminal's and focuses it on a click.
    pub(crate) fn spawn(address: BusAddress, desktop_entry: Option<String>) -> Self {
        let (calls, incoming) = mpsc::channel::<DesktopCall>();
        let _ = std::thread::Builder::new()
            .name("desktop-notifications".into())
            .spawn(move || {
                let mut connection: Option<Connection> = None;
                // Notification ids by key, for replacing and closing.
                let mut shown = BTreeMap::<String, u32>::new();
                for call in incoming {
                    // One reconnect per call: the daemon may have restarted.
                    for _ in 0..2 {
                        if connection.is_none() {
                            connection = Connection::open(&address).ok();
                        }
                        let Some(open) = connection.as_mut() else {
                            break;
                        };
                        match open.apply(&call, &mut shown, desktop_entry.as_deref()) {
                            Ok(()) => break,
                            Err(_) => connection = None,
                        }
                    }
                }
            });
        Self { calls }
    }

    pub(crate) fn send(&self, call: DesktopCall) {
        let _ = self.calls.send(call);
    }
}

/// One authenticated connection to the session bus.
pub(crate) struct Connection {
    stream: UnixStream,
    serial: u32,
}

impl Connection {
    pub(crate) fn open(address: &BusAddress) -> io::Result<Self> {
        let stream = match address {
            BusAddress::Path(path) => UnixStream::connect(path)?,
            BusAddress::Abstract(name) => {
                #[cfg(target_os = "linux")]
                {
                    use std::os::linux::net::SocketAddrExt;
                    let address = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
                    UnixStream::connect_addr(&address)?
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = name;
                    return Err(io::Error::other("abstract sockets need Linux"));
                }
            }
        };
        stream.set_read_timeout(Some(BUS_TIMEOUT))?;
        stream.set_write_timeout(Some(BUS_TIMEOUT))?;
        let mut connection = Self { stream, serial: 0 };
        connection.authenticate()?;
        connection.call(&hello(connection.serial + 1))?;
        Ok(connection)
    }

    fn authenticate(&mut self) -> io::Result<()> {
        let uid = rustix::process::getuid().as_raw().to_string();
        let hex: String = uid.bytes().map(|byte| format!("{byte:02x}")).collect();
        self.stream
            .write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())?;
        let line = read_line(&mut self.stream)?;
        if !line.starts_with("OK ") {
            return Err(io::Error::other(format!("the session bus refused: {line}")));
        }
        self.stream.write_all(b"BEGIN\r\n")
    }

    /// Sends a method call and returns the body of its reply and whether
    /// that is little-endian.
    fn call(&mut self, message: &[u8]) -> io::Result<(bool, Vec<u8>)> {
        self.serial += 1;
        let serial = self.serial;
        self.stream.write_all(message)?;
        // Signals such as NameAcquired may come first.
        for _ in 0..64 {
            let reply = read_message(&mut self.stream)?;
            if reply.reply_serial == Some(serial) {
                return match reply.kind {
                    METHOD_RETURN => Ok((reply.little, reply.body)),
                    _ => Err(io::Error::other("the bus returned an error")),
                };
            }
        }
        Err(io::Error::other("no reply from the bus"))
    }

    fn apply(
        &mut self,
        call: &DesktopCall,
        shown: &mut BTreeMap<String, u32>,
        desktop_entry: Option<&str>,
    ) -> io::Result<()> {
        match call {
            DesktopCall::Notify { key, summary, body } => {
                let replaces = shown.get(key).copied().unwrap_or(0);
                let message = notify(self.serial + 1, replaces, summary, body, desktop_entry);
                let (little, reply) = self.call(&message)?;
                let id = reply
                    .get(..4)
                    .map(|bytes| {
                        let bytes: [u8; 4] = bytes.try_into().expect("four bytes");
                        if little {
                            u32::from_le_bytes(bytes)
                        } else {
                            u32::from_be_bytes(bytes)
                        }
                    })
                    .ok_or_else(|| io::Error::other("Notify returned no id"))?;
                shown.insert(key.clone(), id);
                Ok(())
            }
            DesktopCall::Close { key } => match shown.remove(key) {
                Some(id) => self.call(&close(self.serial + 1, id)).map(drop),
                None => Ok(()),
            },
        }
    }
}

fn read_line(stream: &mut UnixStream) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8];
    while !line.ends_with(b"\r\n") {
        if line.len() > 512 {
            return Err(io::Error::other("overlong authentication line"));
        }
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|_| io::Error::other("authentication line is not UTF-8"))
}

const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;

/// Header field codes.
const PATH: u8 = 1;
const INTERFACE: u8 = 2;
const MEMBER: u8 = 3;
const REPLY_SERIAL: u8 = 5;
const DESTINATION: u8 = 6;
const SENDER: u8 = 7;
const SIGNATURE: u8 = 8;

/// Little-endian D-Bus marshalling. Offsets count from the start of the
/// header or of the body, both of which start 8-aligned in a message.
#[derive(Default)]
struct Marshal(Vec<u8>);

impl Marshal {
    fn pad(&mut self, alignment: usize) {
        while self.0.len() % alignment != 0 {
            self.0.push(0);
        }
    }
    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u32(&mut self, value: u32) {
        self.pad(4);
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn i32(&mut self, value: i32) {
        self.pad(4);
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn string(&mut self, value: &str) {
        self.u32(value.len() as u32);
        self.0.extend_from_slice(value.as_bytes());
        self.0.push(0);
    }
    fn signature(&mut self, value: &str) {
        self.0.push(value.len() as u8);
        self.0.extend_from_slice(value.as_bytes());
        self.0.push(0);
    }
    /// An array whose elements align to `alignment`.
    fn array(&mut self, alignment: usize, elements: impl FnOnce(&mut Self)) {
        self.u32(0);
        let length_at = self.0.len() - 4;
        self.pad(alignment);
        let start = self.0.len();
        elements(self);
        let length = (self.0.len() - start) as u32;
        self.0[length_at..length_at + 4].copy_from_slice(&length.to_le_bytes());
    }
    fn field(&mut self, code: u8, kind: &str, value: &str) {
        self.pad(8);
        self.byte(code);
        self.signature(kind);
        match kind {
            "g" => self.signature(value),
            _ => self.string(value),
        }
    }
}

/// A method call message.
fn method_call(
    serial: u32,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    signature: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut header = Marshal::default();
    header.byte(b'l');
    header.byte(METHOD_CALL);
    header.byte(0);
    header.byte(1);
    header.u32(body.len() as u32);
    header.u32(serial);
    header.array(8, |fields| {
        fields.field(PATH, "o", path);
        fields.field(INTERFACE, "s", interface);
        fields.field(MEMBER, "s", member);
        fields.field(DESTINATION, "s", destination);
        if !signature.is_empty() {
            fields.field(SIGNATURE, "g", signature);
        }
    });
    header.pad(8);
    header.0.extend_from_slice(body);
    header.0
}

fn hello(serial: u32) -> Vec<u8> {
    method_call(
        serial,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "Hello",
        "",
        &[],
    )
}

/// `Notify(app_name, replaces_id, app_icon, summary, body, actions, hints,
/// expire_timeout)`, critical so that GNOME keeps it on screen until it is
/// read or closed.
fn notify(
    serial: u32,
    replaces: u32,
    summary: &str,
    body: &str,
    desktop_entry: Option<&str>,
) -> Vec<u8> {
    let mut message = Marshal::default();
    message.string("nix-secrets");
    message.u32(replaces);
    message.string("dialog-password");
    message.string(summary);
    message.string(body);
    message.array(4, |_| {});
    message.array(8, |hints| {
        hints.pad(8);
        hints.string("urgency");
        hints.signature("y");
        hints.byte(2);
        if let Some(entry) = desktop_entry {
            hints.pad(8);
            hints.string("desktop-entry");
            hints.signature("s");
            hints.string(entry);
        }
    });
    message.i32(-1);
    method_call(
        serial,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
        "Notify",
        "susssasa{sv}i",
        &message.0,
    )
}

fn close(serial: u32, id: u32) -> Vec<u8> {
    let mut message = Marshal::default();
    message.u32(id);
    method_call(
        serial,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
        "CloseNotification",
        "u",
        &message.0,
    )
}

/// A message read from the bus, as far as the client needs it.
pub(crate) struct Message {
    pub(crate) kind: u8,
    pub(crate) reply_serial: Option<u32>,
    // The tests' notification daemon answers by these.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) member: Option<String>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) sender: Option<String>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) serial: u32,
    pub(crate) little: bool,
    pub(crate) body: Vec<u8>,
}

pub(crate) fn read_message(stream: &mut impl Read) -> io::Result<Message> {
    let mut fixed = [0u8; 16];
    stream.read_exact(&mut fixed)?;
    let little = match fixed[0] {
        b'l' => true,
        b'B' => false,
        _ => return Err(io::Error::other("bad message endianness")),
    };
    let number = |bytes: &[u8]| {
        let bytes: [u8; 4] = bytes.try_into().expect("four bytes");
        if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    let body_length = number(&fixed[4..8]) as usize;
    let serial = number(&fixed[8..12]);
    let fields_length = number(&fixed[12..16]) as usize;
    let header_length = (16 + fields_length).div_ceil(8) * 8;
    if header_length + body_length > MAX_MESSAGE {
        return Err(io::Error::other("oversized bus message"));
    }
    let mut rest = vec![0u8; header_length - 16 + body_length];
    stream.read_exact(&mut rest)?;
    let mut message = fixed.to_vec();
    message.extend_from_slice(&rest);
    let mut reply_serial = None;
    let mut member = None;
    let mut sender = None;
    let mut at = 16;
    let end = 16 + fields_length;
    let truncated = || io::Error::other("truncated header field");
    while at < end {
        at = at.div_ceil(8) * 8;
        let code = *message.get(at).ok_or_else(truncated)?;
        let length = *message.get(at + 1).ok_or_else(truncated)? as usize;
        let kind = message.get(at + 2..at + 2 + length).ok_or_else(truncated)?.to_vec();
        at += 2 + length + 1;
        match kind.as_slice() {
            b"u" => {
                at = at.div_ceil(4) * 4;
                let value = number(message.get(at..at + 4).ok_or_else(truncated)?);
                if code == REPLY_SERIAL {
                    reply_serial = Some(value);
                }
                at += 4;
            }
            b"s" | b"o" => {
                at = at.div_ceil(4) * 4;
                let length = number(message.get(at..at + 4).ok_or_else(truncated)?) as usize;
                let text = message.get(at + 4..at + 4 + length).ok_or_else(truncated)?;
                let text = String::from_utf8_lossy(text).into_owned();
                match code {
                    MEMBER => member = Some(text),
                    SENDER => sender = Some(text),
                    _ => {}
                }
                at += 4 + length + 1;
            }
            b"g" => {
                let length = *message.get(at).ok_or_else(truncated)? as usize;
                at += 1 + length + 1;
            }
            _ => return Err(io::Error::other("unexpected header field type")),
        }
    }
    let body = message[header_length..].to_vec();
    Ok(Message {
        kind: fixed[1],
        reply_serial,
        member,
        sender,
        serial,
        little,
        body,
    })
}

#[cfg(test)]
mod tests;
