use super::*;
use crate::model::Model;
use crate::tree::RowCategory;
use crate::ui::{reduce, UiEvent};
use std::time::Instant;

#[test]
fn delayed_backend_response_cannot_stall_terminal_navigation() {
    use crate::client::BackendClient;
    use nix_secrets_core::framing::{read_json, write_json};
    use nix_secrets_core::{Request, Response, Schema};
    use nix_secrets_crypto::AgeCommandProvider;
    use std::os::unix::net::UnixStream;

    let schema = Schema::from_json(r#"{
        "host": {
            "metadata": {"socketPath":"/run/backend.sock", "deployment":{"host":"host", "destination":"operator@host", "port":22}},
            "services": {"test": {"first": {
                "kind":"secret", "recipientPublicKeys":["ssh-ed25519 test"], "recipientIds":["recipient-id"],
                "destination":{"path":"/persistent/secrets/test/service/first", "category":"service", "owner":"test", "group":"test", "mode":"0400"},
                "consumerUnits":[]
            }}},
            "user-alice-services": {}
        }
    }"#).unwrap();
    let (stream, mut remote) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        assert!(matches!(
            read_json::<Request>(&mut remote).unwrap(),
            Some(Request::RegisterFrontend)
        ));
        write_json(&mut remote, &Response::FrontendRegistered).unwrap();
        assert!(matches!(
            read_json::<Request>(&mut remote).unwrap(),
            Some(Request::Get { .. })
        ));
        std::thread::sleep(Duration::from_millis(250));
        write_json(&mut remote, &Response::Secret { envelope: None }).unwrap();
    });
    let controller = Controller::new(
        BackendClient::new(stream),
        schema,
        AgeCommandProvider::default(),
        vec![],
    )
    .unwrap();
    let mut writer = AsyncWriter::spawn(controller, PathBuf::from("/nonexistent/backend.sock"));
    let make_row = |name: &str| Row {
        depth: 0,
        name: name.into(),
        path: Some(format!("host.services.test.{name}")),
        is_set: true,
        is_task: false,
        can_generate: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Other,
        human_facing: false,
    };
    let mut model = Model::new(vec![make_row("first"), make_row("second")]);
    let start = Instant::now();
    reduce(&mut model, UiEvent::Character('r'), &mut writer);
    reduce(&mut model, UiEvent::Down, &mut writer);
    assert_eq!(model.selected, 1);
    assert!(start.elapsed() < Duration::from_millis(100));
    server.join().unwrap();
}

#[test]
fn slow_worker_does_not_block_navigation_or_wait_for_result() {
    let (commands, incoming) = mpsc::channel();
    let (outgoing, events) = mpsc::channel();
    let mut writer = AsyncWriter {
        commands,
        events,
        rows: None,
        approvals: vec![],
        completions: vec![],
        busy: false,
    };
    let worker = std::thread::spawn(move || {
        assert!(matches!(incoming.recv().unwrap(), Command::Reveal(_)));
        std::thread::sleep(Duration::from_millis(250));
        outgoing
            .send(Event::Completion(Completion::Failed(
                "simulated remote error".into(),
            )))
            .unwrap();
    });
    let make_row = |name: &str| Row {
        depth: 0,
        name: name.into(),
        path: Some(format!("host.services.test.{name}")),
        is_set: true,
        is_task: false,
        can_generate: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Other,
        human_facing: false,
    };
    let mut model = Model::new(vec![make_row("first"), make_row("second")]);
    let start = Instant::now();
    reduce(&mut model, UiEvent::Character('r'), &mut writer);
    reduce(&mut model, UiEvent::Down, &mut writer);
    assert_eq!(model.selected, 1);
    assert!(start.elapsed() < Duration::from_millis(100));
    worker.join().unwrap();
    assert!(matches!(
        writer.poll_completion(),
        Some(Completion::Failed(_))
    ));
}
