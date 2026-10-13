//! The real TUI on a real pseudo-terminal (util-linux `script`) as GNOME
//! Console runs it, with a real backend and a real `nix-secrets procedure`:
//! a new prompt rings the bell, sets the title and raises a desktop
//! notification over the session bus, without escape sequences VTE
//! ignores; when the requester dies, the step shows as failed and that is
//! announced too. The session bus is a stand-in notification daemon on a
//! private socket that speaks the D-Bus wire protocol.
use nix_secrets_core::{Backend, Schema, SecretStore};
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::client::BackendClient;
use serde_json::json;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const TOKEN: &str = "host.services.app.token";

/// One call the stand-in daemon received: member, summary and body.
#[derive(Debug)]
struct Call {
    member: String,
    strings: Vec<String>,
}

fn align(at: usize, to: usize) -> usize {
    at.div_ceil(to) * to
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// Reads one little-endian message: its serial, member and leading strings
/// of the body (for Notify: app name, then after the id the icon, summary
/// and body).
fn read_call(stream: &mut UnixStream) -> std::io::Result<(u32, Call)> {
    let mut fixed = [0u8; 16];
    stream.read_exact(&mut fixed)?;
    assert_eq!(fixed[0], b'l');
    let body_length = u32_at(&fixed, 4) as usize;
    let serial = u32_at(&fixed, 8);
    let fields = u32_at(&fixed, 12) as usize;
    let header = align(16 + fields, 8);
    let mut rest = vec![0; header - 16 + body_length];
    stream.read_exact(&mut rest)?;
    let mut message = fixed.to_vec();
    message.extend(rest);
    let mut member = String::new();
    let mut at = 16;
    while at < 16 + fields {
        at = align(at, 8);
        let code = message[at];
        let kind = message[at + 2];
        at += 4;
        match kind {
            b's' | b'o' => {
                at = align(at, 4);
                let length = u32_at(&message, at) as usize;
                if code == 3 {
                    member = String::from_utf8(message[at + 4..at + 4 + length].to_vec()).unwrap();
                }
                at += 4 + length + 1;
            }
            b'g' => at += message[at] as usize + 2,
            b'u' => at = align(at, 4) + 4,
            other => panic!("header field type {other}"),
        }
    }
    let body = &message[header..];
    let mut strings = Vec::new();
    if member == "Notify" {
        let mut at = 0;
        let string = |at: &mut usize| {
            *at = align(*at, 4);
            let length = u32_at(body, *at) as usize;
            let text = String::from_utf8(body[*at + 4..*at + 4 + length].to_vec()).unwrap();
            *at += 4 + length + 1;
            text
        };
        strings.push(string(&mut at));
        at = align(at, 4) + 4;
        string(&mut at);
        strings.push(string(&mut at));
        strings.push(string(&mut at));
    }
    Ok((serial, Call { member, strings }))
}

fn reply(stream: &mut UnixStream, serial: &mut u32, to: u32, signature: &str, body: &[u8]) {
    *serial += 1;
    let mut fields = Vec::new();
    fields.extend([5, 1, b'u', 0]);
    fields.extend(to.to_le_bytes());
    if !signature.is_empty() {
        fields.extend([8, 1, b'g', 0, signature.len() as u8]);
        fields.extend(signature.as_bytes());
        fields.push(0);
    }
    let mut message = vec![b'l', 2, 0, 1];
    message.extend((body.len() as u32).to_le_bytes());
    message.extend(serial.to_le_bytes());
    message.extend((fields.len() as u32).to_le_bytes());
    message.extend(fields);
    while message.len() % 8 != 0 {
        message.push(0);
    }
    message.extend(body);
    stream.write_all(&message).unwrap();
}

/// A notification daemon reached directly on `socket`.
fn notification_daemon(socket: &Path) -> mpsc::Receiver<Call> {
    let listener = UnixListener::bind(socket).unwrap();
    let (calls, received) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let calls = calls.clone();
            std::thread::spawn(move || {
                let mut line = Vec::new();
                let mut byte = [0u8];
                while !line.ends_with(b"BEGIN\r\n") {
                    if stream.read_exact(&mut byte).is_err() {
                        return;
                    }
                    line.push(byte[0]);
                    if line.ends_with(b"\r\n") && line.windows(4).any(|w| w == b"AUTH") {
                        assert!(line.starts_with(b"\0AUTH EXTERNAL "), "{line:?}");
                        stream.write_all(b"OK 0123456789abcdef0123456789abcdef\r\n").unwrap();
                        line.clear();
                    }
                }
                let mut serial = 0;
                let mut next_id = 0u32;
                while let Ok((to, call)) = read_call(&mut stream) {
                    match call.member.as_str() {
                        "Hello" => {
                            let mut body = 4u32.to_le_bytes().to_vec();
                            body.extend(b":1.1\0");
                            reply(&mut stream, &mut serial, to, "s", &body);
                        }
                        "Notify" => {
                            next_id += 1;
                            reply(&mut stream, &mut serial, to, "u", &next_id.to_le_bytes());
                        }
                        _ => reply(&mut stream, &mut serial, to, "", &[]),
                    }
                    if call.member != "Hello" && calls.send(call).is_err() {
                        return;
                    }
                }
            });
        }
    });
    received
}

/// Kills a process group on drop.
struct Group(Child);

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.0.wait();
    }
}

#[test]
fn gnome_console_gets_a_bus_notification_and_a_dead_requester_ends_its_step_visibly() {
    let root = tempfile::tempdir().unwrap();
    let identity = root.path().join("identity");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&identity)
        .status()
        .unwrap()
        .success());
    let public = std::fs::read_to_string(identity.with_extension("pub")).unwrap();
    let public = public.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let runtime = root.path().join("runtime");
    let sockets = runtime.join("nix-secrets");
    std::fs::create_dir_all(&sockets).unwrap();
    for directory in [&runtime, &sockets] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let repository = root.path().join("repository");
    std::fs::create_dir(&repository).unwrap();
    let socket = sockets.join(nix_secrets_manager::startup::socket_name(&repository));
    let schema_json = json!({"host": {
        "metadata": {"socketPath": socket,
            "deployment": {"host": "host", "destination": "forward@host", "port": 22}},
        "services": {"app": {"token": {
            "kind": "secret", "description": "API token",
            "recipientPublicKeys": [public], "recipientIds": ["operator"],
            "consumerUnits": [], "valueType": "password",
            "destination": {"path": "/persistent/secrets/app/service/token",
                "category": "service", "owner": "root", "group": "root", "mode": "0400"}
        }}}
    }})
    .to_string();
    let schema = Schema::from_json(&schema_json).unwrap();
    // The backend the TUI finds on its socket, so it starts none.
    let backend = Backend::bind(
        &socket,
        schema,
        SecretStore::new(repository.join("nix-secrets.toml")),
    )
    .unwrap();
    std::thread::spawn(move || backend.serve());
    let mut client = BackendClient::new(UnixStream::connect(&socket).unwrap());
    client
        .set(
            &nix_secrets_core::SecretPath::parse(TOKEN).unwrap(),
            b"token-value",
            &[nix_secrets_crypto::Recipient {
                id: "operator",
                ssh_public_key: &public,
            }],
            &AgeCommandProvider::identity_file(&identity),
        )
        .unwrap();
    // `nix eval` of the repository prints the schema.
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let schema_file = root.path().join("schema.json");
    std::fs::write(&schema_file, &schema_json).unwrap();
    let nix = bin.join("nix");
    std::fs::write(
        &nix,
        format!(
            "#!/bin/sh\n[ \"$1\" = eval ] || exit 1\nexec cat '{}'\n",
            schema_file.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&nix, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bus = root.path().join("bus");
    let calls = notification_daemon(&bus);
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let frontend = env!("CARGO_BIN_EXE_nix-secrets");
    let tui = format!(
        "stty rows 40 cols 140; exec '{frontend}' --secret-identity '{}' -- '{}'",
        identity.display(),
        repository.display()
    );
    let mut terminal = Command::new("script");
    terminal
        .args(["-q", "-f", "-e", "-c", &tui, "/dev/null"])
        .env_clear()
        .env("PATH", &path)
        // Else `script` runs the passwd shell, `/noshell` in the Nix sandbox.
        .env(
            "SHELL",
            std::env::var_os("SHELL")
                .filter(|shell| !shell.is_empty())
                .unwrap_or_else(|| "/bin/sh".into()),
        )
        .env("HOME", root.path())
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("TERM", "xterm-256color")
        .env("TERM_PROGRAM", "kgx")
        .env("VTE_VERSION", "8401")
        .env("WAYLAND_DISPLAY", "wayland-test")
        .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={}", bus.display()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(root.path().join("script.err")).unwrap())
        .process_group(0);
    let mut terminal = Group(terminal.spawn().expect("util-linux script is required"));
    let mut keys = terminal.0.stdin.take().unwrap();
    let mut screen = terminal.0.stdout.take().unwrap();
    let raw = Arc::new(Mutex::new(Vec::new()));
    let (queries, answers) = mpsc::channel::<()>();
    {
        let raw = Arc::clone(&raw);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 65536];
            while let Ok(read) = screen.read(&mut buffer) {
                if read == 0 {
                    return;
                }
                let mut raw = raw.lock().unwrap();
                raw.extend_from_slice(&buffer[..read]);
                if buffer[..read].windows(4).any(|w| w == b"\x1b[6n") {
                    let _ = queries.send(());
                }
            }
        });
    }
    std::thread::spawn(move || {
        while answers.recv().is_ok() {
            if keys.write_all(b"\x1b[1;1R").is_err() {
                return;
            }
        }
    });
    let output = || String::from_utf8_lossy(&raw.lock().unwrap()).into_owned();
    let wait_for = |what: &str| {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !output().contains(what) {
            assert!(
                Instant::now() < deadline,
                "no {what:?} in:\n{}\nscript: {}",
                output(),
                std::fs::read_to_string(root.path().join("script.err")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    wait_for("Ready");
    let mut procedure = Command::new(frontend);
    procedure
        .args(["procedure", "--title", "Update host", "--steps", "2", "--backend-socket"])
        .arg(&socket)
        .args([
            "--",
            "sh",
            "-c",
            r#""$NIX_SECRETS" with-secrets --backend-socket "$SOCKET" host.services.app.token -- true"#,
        ])
        .env("NIX_SECRETS", frontend)
        .env("SOCKET", &socket)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env_remove("NIX_SECRETS_PROCEDURE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let procedure = Group(procedure.spawn().unwrap());
    let next = || {
        calls
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("no notification; terminal:\n{}", output()))
    };
    let announced = next();
    assert_eq!(announced.member, "Notify", "{announced:?}");
    assert_eq!(
        announced.strings,
        [
            "nix-secrets",
            "nix-secrets: approval needed",
            "Update host · step 1/2: release 1 secret value · denies in 120 s"
        ]
    );
    wait_for("\x1b]2;(!) nix-secrets: approval needed\x07");
    let shown = output();
    assert!(shown.contains('\x07'), "the bell rings");
    // VTE shows none of these; they would only notify twice elsewhere.
    for ignored in ["\x1b]777;", "\x1b]9;", "\x1b]99;"] {
        assert!(!shown.contains(ignored), "{ignored:?} sent to GNOME Console");
    }
    // The requester dies before anyone answers.
    drop(procedure);
    let closed = next();
    assert_eq!(closed.member, "CloseNotification", "{closed:?}");
    let missed = next();
    assert_eq!(missed.member, "Notify", "{missed:?}");
    assert_eq!(
        missed.strings[1..],
        [
            "nix-secrets: step failed",
            "Update host failed at step 1/2: release 1 secret value"
        ]
    );
    wait_for("\x1b]2;nix-secrets\x07\x1b[23;2t");
    assert!(
        calls.recv_timeout(Duration::from_millis(500)).is_err(),
        "each event notifies once"
    );
}
