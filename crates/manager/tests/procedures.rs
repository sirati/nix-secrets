//! Procedures end to end: `nix-secrets procedure` registers with a real
//! backend, the requesters it starts join it as numbered steps, the operator
//! channel sees them grouped, several procedures wait at once, only
//! descendants may join, and a cancelled countdown keeps the requester
//! waiting past the backend's own deadline.
use nix_secrets_core::framing::{read_json, write_json};
use nix_secrets_core::procedure::ProcedureStep;
use nix_secrets_core::{Backend, Request, Response, Schema, SecretStore};
use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_manager::client::BackendClient;
use nix_secrets_manager::operator_channel::{
    self, ChannelEvent, Decision, OperatorInput, SecretPrompt,
};
use serde_json::json;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

const TOKEN: &str = "host.services.app.token";

struct Fixture {
    temp: tempfile::TempDir,
    socket: PathBuf,
    schema: Schema,
    identity: PathBuf,
}

/// A backend whose requests with a countdown give up after `deadline`.
fn fixture(deadline: Duration) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("id");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&identity)
        .status()
        .unwrap()
        .success());
    let public = std::fs::read_to_string(identity.with_extension("pub")).unwrap();
    let public = public.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let socket = temp.path().join("backend.sock");
    let schema = Schema::from_json(
        &json!({"host": {
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
        .to_string(),
    )
    .unwrap();
    let backend = Backend::bind(
        &socket,
        schema.clone(),
        SecretStore::new(temp.path().join("nix-secrets.toml")),
    )
    .unwrap()
    .with_operator_timing(deadline, Duration::from_millis(200));
    std::thread::spawn(move || backend.serve());
    let fixture = Fixture {
        temp,
        socket,
        schema,
        identity,
    };
    // The value is stored, so a request for it reaches the operator.
    let mut client = BackendClient::new(UnixStream::connect(&fixture.socket).unwrap());
    let key = std::fs::read_to_string(fixture.identity.with_extension("pub")).unwrap();
    let recipient = nix_secrets_crypto::Recipient {
        id: "operator",
        ssh_public_key: key.trim(),
    };
    client
        .set(
            &nix_secrets_core::SecretPath::parse(TOKEN).unwrap(),
            b"token-value",
            &[recipient],
            &AgeCommandProvider::identity_file(&fixture.identity),
        )
        .unwrap();
    fixture
}

struct Operator {
    events: Receiver<ChannelEvent>,
    inputs: Sender<OperatorInput>,
}

impl Fixture {
    fn attach(&self) -> Operator {
        let (events, channel) = mpsc::channel();
        let (inputs, incoming) = mpsc::channel();
        let (socket, schema) = (self.socket.clone(), self.schema.clone());
        let provider = AgeCommandProvider::identity_file(&self.identity);
        std::thread::spawn(move || {
            let _ = operator_channel::run(&socket, &schema, &provider, "test", &events, &incoming);
        });
        let operator = Operator {
            events: channel,
            inputs,
        };
        assert!(matches!(operator.next(), ChannelEvent::Attached));
        operator
    }

    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nix-secrets"));
        command
            .args(arguments)
            .env("NIX_SECRETS", env!("CARGO_BIN_EXE_nix-secrets"))
            .env("SOCKET", &self.socket)
            .env("OUT", self.temp.path())
            .env("XDG_RUNTIME_DIR", self.temp.path())
            .env_remove("NIX_SECRETS_PROCEDURE")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// `nix-secrets procedure --title TITLE -- sh -c SCRIPT` in the
    /// background.
    fn procedure(&self, title: &str, script: &str) -> Child {
        self.command(&["procedure", "--title", title, "--steps", "3", "--backend-socket"])
            .arg(&self.socket)
            .args(["--", "sh", "-c", script])
            .spawn()
            .unwrap()
    }
}

/// Asks for the token inside the procedure; prints why it failed.
const ASK: &str = r#""$NIX_SECRETS" with-secrets --backend-socket "$SOCKET" host.services.app.token -- true"#;

impl Operator {
    fn next(&self) -> ChannelEvent {
        self.events
            .recv_timeout(Duration::from_secs(30))
            .expect("the operator channel sent nothing")
    }

    /// The next prompt, collecting procedure news on the way.
    fn prompt(&self, steps: &mut Vec<ProcedureStep>) -> SecretPrompt {
        loop {
            match self.next() {
                ChannelEvent::Prompt(prompt) => return prompt,
                ChannelEvent::Procedure(step) => steps.push(step),
                ChannelEvent::ProcedureEnded(..) | ChannelEvent::Finished { .. } => {}
                _ => panic!("unexpected channel event"),
            }
        }
    }

    fn decide(&self, prompt: &SecretPrompt, approved: bool) {
        self.inputs
            .send(
                Decision {
                    id: prompt.id.clone(),
                    approved,
                }
                .into(),
            )
            .unwrap();
    }

    /// Waits for the end of procedure `id`; returns its exit code.
    fn until_ended(&self, id: &str) -> Option<i32> {
        let until = Instant::now() + Duration::from_secs(30);
        while Instant::now() < until {
            if let Ok(ChannelEvent::ProcedureEnded(ended, exit_code)) =
                self.events.recv_timeout(Duration::from_secs(1))
            {
                if ended == id {
                    return exit_code;
                }
            }
        }
        panic!("procedure {id} did not end");
    }
}

fn finish(child: Child) -> Output {
    child.wait_with_output().unwrap()
}

#[test]
fn a_procedure_numbers_its_requests_as_steps_of_one_titled_group() {
    let fixture = fixture(Duration::from_secs(600));
    let operator = fixture.attach();
    // A frontend is registered, so the deployment step is queued.
    let mut frontend = BackendClient::new(UnixStream::connect(&fixture.socket).unwrap());
    frontend.register_frontend().unwrap();
    let child = fixture.procedure(
        "Update host",
        &format!(
            "{ASK}; {ASK}; \"$NIX_SECRETS\" deploy --backend-socket \"$SOCKET\" host"
        ),
    );
    let mut steps = Vec::new();
    let first = operator.prompt(&mut steps);
    let procedure = first.procedure.clone().expect("the request joined the procedure");
    assert_eq!(procedure.title, "Update host");
    assert_eq!((procedure.step, procedure.steps), (1, Some(3)));
    assert_eq!(procedure.label, "release 1 secret value");
    assert!(first.deadline.is_some(), "the first step counts down");
    assert!(steps.iter().any(|step| step.id == procedure.id && step.step == 0));
    operator.decide(&first, false);
    let second = operator.prompt(&mut steps);
    let step = second.procedure.clone().unwrap();
    assert_eq!((step.id.as_str(), step.step), (procedure.id.as_str(), 2));
    assert!(second.deadline.is_none(), "later steps never deny on their own");
    operator.decide(&second, false);
    // The deployment is step 3 of the same procedure.
    let mut claimed = None;
    let until = Instant::now() + Duration::from_secs(30);
    while claimed.is_none() && Instant::now() < until {
        claimed = frontend.poll_and_claim_step().unwrap();
        std::thread::sleep(Duration::from_millis(50));
    }
    let (request, _, deployment) = claimed.expect("the deployment was queued");
    assert_eq!(request.target, "host");
    let deployment = deployment.expect("the deployment belongs to the procedure");
    assert_eq!((deployment.id.as_str(), deployment.step), (procedure.id.as_str(), 3));
    assert!(deployment.deployment);
    assert_eq!(deployment.label, "deploy secrets to host");
    let output = finish(child);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(operator.until_ended(&procedure.id), Some(0));
}

#[test]
fn the_operator_channel_learns_how_the_command_exited() {
    let fixture = fixture(Duration::from_secs(600));
    let operator = fixture.attach();
    let child = fixture.procedure("Update host", "exit 3");
    let id = loop {
        if let ChannelEvent::Procedure(step) = operator.next() {
            break step.id;
        }
    };
    assert_eq!(operator.until_ended(&id), Some(3));
    assert_eq!(finish(child).status.code(), Some(3));
}

#[test]
fn two_procedures_wait_at_once_and_are_answered_in_any_order() {
    let fixture = fixture(Duration::from_secs(600));
    let operator = fixture.attach();
    let first = fixture.procedure("Update one", ASK);
    let mut steps = Vec::new();
    let one = operator.prompt(&mut steps);
    let second = fixture.procedure("Install two", ASK);
    let two = operator.prompt(&mut steps);
    let (one_procedure, two_procedure) =
        (one.procedure.clone().unwrap(), two.procedure.clone().unwrap());
    assert_ne!(one_procedure.id, two_procedure.id);
    assert_eq!(two_procedure.title, "Install two");
    // Both are first steps of their own procedures.
    assert_eq!((one_procedure.step, two_procedure.step), (1, 1));
    operator.decide(&two, false);
    let output = finish(second);
    assert!(String::from_utf8_lossy(&output.stderr).contains("denied"), "{output:?}");
    operator.decide(&one, false);
    let output = finish(first);
    assert!(String::from_utf8_lossy(&output.stderr).contains("denied"), "{output:?}");
}

#[test]
fn only_descendants_of_the_procedure_may_join_it() {
    let fixture = fixture(Duration::from_secs(600));
    let operator = fixture.attach();
    let stop = fixture.temp.path().join("stop");
    let holder = fixture.procedure(
        "Update host",
        r#"printf %s "$NIX_SECRETS_PROCEDURE" > "$OUT/token"; while [ ! -e "$OUT/stop" ]; do sleep 0.05; done"#,
    );
    let token_file = fixture.temp.path().join("token");
    let until = Instant::now() + Duration::from_secs(30);
    while std::fs::read_to_string(&token_file).map_or(true, |token| token.is_empty()) {
        assert!(Instant::now() < until, "the procedure never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    let token = std::fs::read_to_string(&token_file).unwrap();
    // The token alone does not admit a process outside the procedure.
    let output = fixture
        .command(&["with-secrets", "--backend-socket"])
        .arg(&fixture.socket)
        .args([TOKEN, "--", "true"])
        .env("NIX_SECRETS_PROCEDURE", &token)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not belong to procedure"), "{stderr}");
    // Nobody was asked.
    while let Ok(event) = operator.events.recv_timeout(Duration::from_millis(300)) {
        assert!(!matches!(event, ChannelEvent::Prompt(_)), "a foreign request was shown");
    }
    std::fs::write(&stop, "").unwrap();
    assert!(finish(holder).status.success());
    // Once it ended, its token is worthless.
    let output = fixture
        .command(&["with-secrets", "--backend-socket"])
        .arg(&fixture.socket)
        .args([TOKEN, "--", "true"])
        .env("NIX_SECRETS_PROCEDURE", &token)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&output.stderr).contains("has ended"), "{output:?}");
}

#[test]
fn a_cancelled_countdown_keeps_the_requester_waiting_past_the_backend_deadline() {
    let deadline = Duration::from_secs(2);
    // A request of its own is told as well as a step of a procedure.
    for (cancel, in_procedure) in [(false, true), (true, true), (true, false)] {
        let fixture = fixture(deadline);
        let operator = fixture.attach();
        let child = if in_procedure {
            fixture.procedure("Update host", ASK)
        } else {
            fixture
                .command(&["with-secrets", "--backend-socket"])
                .arg(&fixture.socket)
                .args([TOKEN, "--", "true"])
                .spawn()
                .unwrap()
        };
        let prompt = operator.prompt(&mut Vec::new());
        assert!(prompt.deadline.is_some());
        if cancel {
            operator
                .inputs
                .send(OperatorInput::CancelCountdown(prompt.id.clone()))
                .unwrap();
        }
        // Well past the backend's deadline for an unanswered first step.
        std::thread::sleep(deadline * 2);
        operator.decide(&prompt, false);
        let output = finish(child);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        if cancel {
            assert!(
                stderr.contains("operator cancelled the auto-reject countdown; waiting"),
                "{stderr}"
            );
            assert!(stderr.contains("the operator denied the secret request"), "{stderr}");
        } else {
            assert!(stderr.contains("did not answer in time"), "{stderr}");
        }
    }
}

#[test]
fn requests_from_older_requesters_without_procedure_fields_still_work() {
    let fixture = fixture(Duration::from_secs(600));
    let operator = fixture.attach();
    // Exactly what a requester from before procedures sends.
    let mut stream = UnixStream::connect(&fixture.socket).unwrap();
    write_json(
        &mut stream,
        &json!({"operation": "request-secrets", "identifiers": [TOKEN], "reason": "legacy"}),
    )
    .unwrap();
    let prompt = operator.prompt(&mut Vec::new());
    assert!(prompt.procedure.is_none());
    assert!(prompt.deadline.is_some(), "a request of its own counts down");
    operator
        .inputs
        .send(OperatorInput::CancelCountdown(prompt.id.clone()))
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    operator.decide(&prompt, false);
    // One answer frame, as before: no interim frames for an older requester.
    match read_json::<Response>(&mut stream).unwrap() {
        Some(Response::Error { message }) => assert!(message.contains("denied"), "{message}"),
        other => panic!("unexpected {other:?}"),
    }
    let _ = Request::EndSecretSession;
}
