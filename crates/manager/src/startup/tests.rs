use super::*;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "manager-start-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

struct FakeLauncher {
    path: std::path::PathBuf,
    starts: usize,
}
impl Launcher for FakeLauncher {
    type Guard = std::thread::JoinHandle<()>;
    fn start(&mut self, _command: &CommandSpec) -> io::Result<Self::Guard> {
        self.starts += 1;
        let listener = UnixListener::bind(&self.path)?;
        Ok(std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let request: Request = read_json(&mut stream).unwrap().unwrap();
                assert!(matches!(request, Request::List));
                write_json(
                    &mut stream,
                    &Response::Secrets {
                        entries: Default::default(),
                    },
                )
                .unwrap();
            }
        }))
    }
}

#[test]
fn starts_once_then_connects_to_same_user_backend() {
    let path = path();
    let mut launcher = FakeLauncher {
        path: path.clone(),
        starts: 0,
    };
    let spec = CommandSpec {
        program: "unused".into(),
        arguments: vec![],
    };
    let connection = match connect_or_start(&path, &spec, &mut launcher, Duration::from_secs(1)) {
        Ok(connection) => connection,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("startup failed: {error}"),
    };
    assert_eq!(launcher.starts, 1);
    drop(connection.stream);
    fs::remove_file(path).unwrap();
}

#[test]
fn starts_new_backend_without_replacing_older_protocol_socket() {
    let repository = path();
    let versioned = repository.with_file_name(socket_name(&repository));
    let legacy =
        repository.with_file_name(socket_name(&repository).replace("backend-v8-", "backend-"));
    let old_listener = UnixListener::bind(&legacy).unwrap();
    let mut launcher = FakeLauncher {
        path: versioned.clone(),
        starts: 0,
    };
    let spec = CommandSpec {
        program: "unused".into(),
        arguments: vec![],
    };
    let connection =
        connect_or_start(&versioned, &spec, &mut launcher, Duration::from_secs(1)).unwrap();
    assert_eq!(launcher.starts, 1);
    assert!(legacy.exists());
    drop(connection);
    drop(old_listener);
    fs::remove_file(versioned).unwrap();
    fs::remove_file(legacy).unwrap();
}

#[test]
fn reports_backend_store_error_instead_of_opaque_readiness_failure() {
    let path = path();
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert!(matches!(
            read_json::<Request>(&mut stream).unwrap(),
            Some(Request::List)
        ));
        write_json(
            &mut stream,
            &Response::Error {
                message: "document format is incompatible".into(),
            },
        )
        .unwrap();
    });
    let error = connect_ready(&path).unwrap_err();
    assert!(error
        .to_string()
        .contains("document format is incompatible"));
    server.join().unwrap();
    fs::remove_file(path).unwrap();
}

#[test]
fn waits_until_a_forwarded_socket_reaches_the_backend() {
    struct DelayedForward {
        path: std::path::PathBuf,
    }

    impl Launcher for DelayedForward {
        type Guard = std::thread::JoinHandle<()>;

        fn start(&mut self, _command: &CommandSpec) -> io::Result<Self::Guard> {
            let listener = UnixListener::bind(&self.path)?;
            Ok(std::thread::spawn(move || {
                let (first, _) = listener.accept().unwrap();
                drop(first); // SSH accepted locally; remote socket is not ready.
                let (mut second, _) = listener.accept().unwrap();
                let request: Request = read_json(&mut second).unwrap().unwrap();
                assert!(matches!(request, Request::List));
                write_json(
                    &mut second,
                    &Response::Secrets {
                        entries: Default::default(),
                    },
                )
                .unwrap();
            }))
        }
    }

    let path = path();
    let spec = CommandSpec {
        program: "unused".into(),
        arguments: vec![],
    };
    let connection = connect_or_start(
        &path,
        &spec,
        &mut DelayedForward { path: path.clone() },
        Duration::from_secs(1),
    )
    .unwrap();
    drop(connection);
    fs::remove_file(path).unwrap();
}

#[test]
fn ephemeral_tunnel_removes_only_its_socket_on_exit() {
    let socket = path();
    let listener = UnixListener::bind(&socket).unwrap();
    let command = CommandSpec {
        program: "sleep".into(),
        arguments: vec!["30".into()],
    };
    let mut launcher = ProcessLauncher::ephemeral(&socket);
    let guard = launcher.start(&command).unwrap();
    drop(guard);
    assert!(!socket.exists());
    drop(listener);
}
