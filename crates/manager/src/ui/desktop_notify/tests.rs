use super::*;
use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

#[test]
fn addresses_parse_with_escapes_and_take_the_first_unix_one() {
    assert_eq!(
        parse_address("unix:path=/run/user/1000/bus"),
        Some(BusAddress::Path("/run/user/1000/bus".into()))
    );
    assert_eq!(
        parse_address("tcp:host=x,port=1;unix:path=/tmp/a%20b,guid=00"),
        Some(BusAddress::Path("/tmp/a b".into()))
    );
    assert_eq!(
        parse_address("unix:abstract=/tmp/dbus-XYZ,guid=1"),
        Some(BusAddress::Abstract(b"/tmp/dbus-XYZ".to_vec()))
    );
    assert_eq!(parse_address("unix:path=/x%zz"), None);
    assert_eq!(parse_address("tcp:host=localhost"), None);
}

#[test]
fn only_a_local_graphical_session_gets_desktop_notifications() {
    let bus = "unix:path=/run/user/1000/bus";
    let local = env(&[("WAYLAND_DISPLAY", "wayland-0"), ("DBUS_SESSION_BUS_ADDRESS", bus)]);
    assert_eq!(
        local_session_bus(&local),
        Some(BusAddress::Path("/run/user/1000/bus".into()))
    );
    let x11 = env(&[("DISPLAY", ":0"), ("DBUS_SESSION_BUS_ADDRESS", bus)]);
    assert!(local_session_bus(&x11).is_some());
    // Over SSH the environment's bus belongs to the remote host.
    for variable in ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"] {
        let remote = env(&[
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("DBUS_SESSION_BUS_ADDRESS", bus),
            (variable, "10.0.0.1 22 10.0.0.2 4242"),
        ]);
        assert_eq!(local_session_bus(&remote), None, "{variable}");
    }
    // A console session without a display gets none.
    assert_eq!(local_session_bus(&env(&[("DBUS_SESSION_BUS_ADDRESS", bus)])), None);
    // Without an address, the runtime directory's bus counts if it exists.
    let runtime = tempfile::tempdir().unwrap();
    let path = runtime.path().to_str().unwrap();
    let missing = env(&[("WAYLAND_DISPLAY", "w"), ("XDG_RUNTIME_DIR", path)]);
    assert_eq!(local_session_bus(&missing), None);
    std::fs::write(runtime.path().join("bus"), "").unwrap();
    assert_eq!(
        local_session_bus(&missing),
        Some(BusAddress::Path(runtime.path().join("bus")))
    );
}

/// A private `dbus-daemon`, stopped on drop.
struct Daemon {
    child: Child,
    address: BusAddress,
    _directory: tempfile::TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn daemon() -> Option<Daemon> {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("bus");
    let config = directory.path().join("session.conf");
    // The session bus policy: one user, everything allowed.
    std::fs::write(
        &config,
        format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
            socket.display()
        ),
    )
    .unwrap();
    let child = match Command::new("dbus-daemon")
        .arg(format!("--config-file={}", config.display()))
        .args(["--nofork", "--nopidfile"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => panic!("dbus-daemon: {error}"),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "dbus-daemon did not listen");
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(Daemon {
        child,
        address: BusAddress::Path(socket),
        _directory: directory,
    })
}

/// Reads the arguments of a message body by signature.
struct Body<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Body<'_> {
    fn align(&mut self, alignment: usize) {
        self.at = self.at.div_ceil(alignment) * alignment;
    }
    fn u32(&mut self) -> u32 {
        self.align(4);
        let value = u32::from_le_bytes(self.bytes[self.at..self.at + 4].try_into().unwrap());
        self.at += 4;
        value
    }
    fn string(&mut self) -> String {
        let length = self.u32() as usize;
        let text = String::from_utf8(self.bytes[self.at..self.at + length].to_vec()).unwrap();
        self.at += length + 1;
        text
    }
    fn signature(&mut self) -> String {
        let length = self.bytes[self.at] as usize;
        let text = String::from_utf8(self.bytes[self.at + 1..self.at + 1 + length].to_vec()).unwrap();
        self.at += length + 2;
        text
    }
}

/// What the notification daemon received in one Notify call.
#[derive(Debug)]
struct Notified {
    replaces: u32,
    summary: String,
    body: String,
    hints: Vec<(String, String)>,
}

fn parse_notify(bytes: &[u8]) -> Notified {
    let mut body = Body { bytes, at: 0 };
    assert_eq!(body.string(), "nix-secrets");
    let replaces = body.u32();
    body.string();
    let summary = body.string();
    let text = body.string();
    assert_eq!(body.u32(), 0, "no actions");
    let length = body.u32() as usize;
    body.align(8);
    let end = body.at + length;
    let mut hints = vec![];
    while body.at < end {
        body.align(8);
        let key = body.string();
        let value = match body.signature().as_str() {
            "y" => {
                let byte = bytes[body.at];
                body.at += 1;
                byte.to_string()
            }
            "s" => body.string(),
            other => panic!("unexpected hint type {other}"),
        };
        hints.push((key, value));
    }
    Notified {
        replaces,
        summary,
        body: text,
        hints,
    }
}

fn method_return(serial: u32, reply_to: &Message, body: &[u8], signature: &str) -> Vec<u8> {
    let mut header = Marshal::default();
    header.byte(b'l');
    header.byte(METHOD_RETURN);
    header.byte(0);
    header.byte(1);
    header.u32(body.len() as u32);
    header.u32(serial);
    header.array(8, |fields| {
        fields.pad(8);
        fields.byte(REPLY_SERIAL);
        fields.signature("u");
        fields.u32(reply_to.serial);
        fields.field(DESTINATION, "s", reply_to.sender.as_deref().unwrap());
        if !signature.is_empty() {
            fields.field(SIGNATURE, "g", signature);
        }
    });
    header.pad(8);
    header.0.extend_from_slice(body);
    header.0
}

/// Claims `org.freedesktop.Notifications` on the bus and answers Notify
/// with increasing ids. Sends what it receives to the test.
fn notification_daemon(address: &BusAddress) -> mpsc::Receiver<(String, Vec<u8>)> {
    let mut server = Connection::open(address).unwrap();
    let mut request = Marshal::default();
    request.string("org.freedesktop.Notifications");
    request.u32(4);
    let message = method_call(
        server.serial + 1,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "RequestName",
        "su",
        &request.0,
    );
    let (_, reply) = server.call(&message).unwrap();
    assert_eq!(reply[..4], 1u32.to_le_bytes(), "primary owner");
    server.stream.set_read_timeout(None).unwrap();
    let (sender, received) = mpsc::channel();
    std::thread::spawn(move || {
        let mut next_id = 7u32;
        while let Ok(message) = read_message(&mut server.stream) {
            if message.kind != METHOD_CALL {
                continue;
            }
            let member = message.member.clone().unwrap_or_default();
            server.serial += 1;
            let reply = if member == "Notify" {
                next_id += 1;
                method_return(server.serial, &message, &next_id.to_le_bytes(), "u")
            } else {
                method_return(server.serial, &message, &[], "")
            };
            server.stream.write_all(&reply).unwrap();
            if sender.send((member, message.body)).is_err() {
                return;
            }
        }
    });
    received
}

#[test]
fn notifications_reach_a_real_bus_replace_each_other_and_close() {
    let Some(daemon) = daemon() else {
        eprintln!("dbus-daemon is not installed; not run");
        return;
    };
    let received = notification_daemon(&daemon.address);
    let desktop = Desktop::spawn(daemon.address.clone(), Some("org.gnome.Console".into()));
    let next = || received.recv_timeout(Duration::from_secs(10)).expect("a call arrives");
    desktop.send(DesktopCall::Notify {
        key: "secret:1".into(),
        summary: "nix-secrets: approval needed".into(),
        body: "Update ns1 · step 1/3: sign closure for ns1 · denies in 120 s".into(),
    });
    let (member, body) = next();
    assert_eq!(member, "Notify");
    let first = parse_notify(&body);
    assert_eq!(first.replaces, 0);
    assert_eq!(first.summary, "nix-secrets: approval needed");
    assert_eq!(
        first.body,
        "Update ns1 · step 1/3: sign closure for ns1 · denies in 120 s"
    );
    assert_eq!(
        first.hints,
        [
            ("urgency".to_owned(), "2".to_owned()),
            ("desktop-entry".to_owned(), "org.gnome.Console".to_owned())
        ]
    );
    // The reminder replaces the announcement.
    desktop.send(DesktopCall::Notify {
        key: "secret:1".into(),
        summary: "nix-secrets: 30 s left to answer".into(),
        body: "Update ns1".into(),
    });
    let (_, body) = next();
    assert_eq!(parse_notify(&body).replaces, 8);
    // Another request gets a notification of its own.
    desktop.send(DesktopCall::Notify {
        key: "secret:2".into(),
        summary: "s".into(),
        body: "b".into(),
    });
    let (_, body) = next();
    assert_eq!(parse_notify(&body).replaces, 0);
    // Answered: its notification goes; closing an unknown key sends nothing.
    desktop.send(DesktopCall::Close { key: "unknown".into() });
    desktop.send(DesktopCall::Close { key: "secret:1".into() });
    let (member, body) = next();
    assert_eq!(member, "CloseNotification");
    assert_eq!(body, 9u32.to_le_bytes(), "the id of the latest notification");
    assert!(received.recv_timeout(Duration::from_millis(200)).is_err());
}

#[test]
fn a_missing_notification_daemon_does_not_block_the_sender() {
    let Some(daemon) = daemon() else {
        eprintln!("dbus-daemon is not installed; not run");
        return;
    };
    let desktop = Desktop::spawn(daemon.address.clone(), None);
    let started = Instant::now();
    for _ in 0..3 {
        desktop.send(DesktopCall::Notify {
            key: "k".into(),
            summary: "s".into(),
            body: "b".into(),
        });
    }
    assert!(started.elapsed() < Duration::from_millis(100));
    // The bus itself answers for the missing name; the client stays usable.
    let mut client = Connection::open(&daemon.address).unwrap();
    let message = notify(client.serial + 1, 0, "s", "b", None);
    assert!(client.call(&message).is_err(), "nobody owns the name");
    let received = notification_daemon(&daemon.address);
    let (_, body) = client
        .call(&notify(client.serial + 1, 0, "s", "b", None))
        .map(|reply| ("Notify".to_owned(), reply.1))
        .unwrap();
    // The id is the daemon's; the earlier sender may still get there first.
    assert_eq!(body.len(), 4);
    let (member, _) = received.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(member, "Notify");
}
