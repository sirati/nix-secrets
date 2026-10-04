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
        display_segments: vec![],
        path: Some(format!("host.services.test.{name}")),
        is_set: true,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Other,
        human_facing: false,
        external_input_required: true,
        required_for_install: false,
        identity: None,
        presentation: None,
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
        profiles: None,
        approvals: vec![],
        completions: vec![],
        busy: false,
        pending: Default::default(),
        drafts: Default::default(),
        activity: None,
        one_password: true,
        socket: None,
        channel: None,
        decisions: None,
        secret_prompts: vec![],
        secret_activity: None,
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
        display_segments: vec![],
        path: Some(format!("host.services.test.{name}")),
        is_set: true,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Other,
        human_facing: false,
        external_input_required: true,
        required_for_install: false,
        identity: None,
        presentation: None,
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

#[test]
fn slow_commands_describe_their_activity_until_completion() {
    let (commands, incoming) = mpsc::channel();
    let (outgoing, events) = mpsc::channel();
    let mut writer = AsyncWriter {
        commands,
        events,
        rows: None,
        profiles: None,
        approvals: vec![],
        completions: vec![],
        busy: false,
        pending: Default::default(),
        drafts: Default::default(),
        activity: None,
        one_password: true,
        socket: None,
        channel: None,
        decisions: None,
        secret_prompts: vec![],
        secret_activity: None,
    };
    assert!(writer.activity().is_none());
    let _ = writer.reveal("host.services.test.first");
    let activity = writer.activity().unwrap();
    assert_eq!(activity.label, "Decrypting host.services.test.first");
    assert!(activity.waits_for_one_password);
    assert!(matches!(incoming.recv().unwrap(), Command::Reveal(_)));
    outgoing
        .send(Event::Completion(Completion::Failed("done".into())))
        .unwrap();
    assert!(writer.activity().is_none());
    assert!(describe(&Command::CopyValue(Zeroizing::new(vec![])), true).is_none());
    let identity_file = describe(&Command::Reveal("x".into()), false).unwrap();
    assert!(!identity_file.waits_for_one_password);
}

#[test]
fn deployment_and_failed_save_keep_the_draft_until_retry_succeeds() {
    use crate::model::Mode;
    use crate::ui::{drive, Frontend};
    use std::collections::VecDeque;
    use std::io;

    let (commands, incoming) = mpsc::channel();
    let (outgoing, events) = mpsc::channel();
    let mut writer = AsyncWriter {
        commands,
        events,
        rows: None,
        profiles: None,
        approvals: vec![],
        completions: vec![],
        busy: false,
        pending: Default::default(),
        drafts: Default::default(),
        activity: None,
        one_password: true,
        socket: None,
        channel: None,
        decisions: None,
        secret_prompts: vec![],
        secret_activity: None,
    };
    assert!(writer.approval(true).is_err());
    assert!(matches!(incoming.recv().unwrap(), Command::Approval(true)));
    let path = "host.services.test.password";
    let mut model = Model::new(vec![Row {
        depth: 0,
        name: "password".into(),
        display_segments: vec![],
        path: Some(path.into()),
        is_set: false,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: RowCategory::Password,
        human_facing: false,
        external_input_required: true,
        required_for_install: false,
        identity: None,
        presentation: None,
    }]);
    model.settings.autosave_unset_on_paste = false;
    struct Terminal {
        events: VecDeque<UiEvent>,
        incoming: Receiver<Command>,
        outgoing: Sender<Event>,
        ticks: usize,
    }
    impl Frontend for Terminal {
        fn draw(&mut self, _: &Model) -> io::Result<()> {
            Ok(())
        }
        fn read(&mut self, _: Duration) -> io::Result<UiEvent> {
            let event = self.events.pop_front().expect("scripted UI event");
            if event == UiEvent::Tick {
                let completion = match self.ticks {
                    0 => {
                        // The save is safely queued behind deployment.
                        Completion::Deployed {
                            generated: vec![],
                            skipped: vec![],
                            summary: None,
                        }
                    }
                    1 | 2 => {
                        let Command::Write { path, value } = self.incoming.recv().unwrap() else {
                            panic!("retry must queue the save")
                        };
                        assert!(value.as_slice() == b"draft!", "draft must survive errors");
                        if self.ticks == 1 {
                            Completion::SaveFailed {
                                path,
                                value,
                                message: "provider unavailable".into(),
                            }
                        } else {
                            Completion::Saved(path)
                        }
                    }
                    _ => unreachable!(),
                };
                self.outgoing.send(Event::Completion(completion)).unwrap();
                self.ticks += 1;
            }
            Ok(event)
        }
    }
    let mut terminal = Terminal {
        events: VecDeque::from([
            UiEvent::Enter,
            UiEvent::Paste(b"draft".to_vec()),
            UiEvent::Character('!'),
            UiEvent::Enter,
            UiEvent::Tick,
            // Dismiss deployment notice; the queued save then fails with its draft.
            UiEvent::Enter,
            UiEvent::Tick,
            // Provider failure also returns to the draft on Escape.
            UiEvent::Escape,
            UiEvent::Enter,
            UiEvent::Tick,
            UiEvent::Escape,
            UiEvent::Escape,
        ]),
        incoming,
        outgoing,
        ticks: 0,
    };
    drive(&mut terminal, &mut writer, &mut model).unwrap();
    assert_eq!(terminal.ticks, 3);
    assert!(model.rows[0].is_set);
    assert!(matches!(model.mode, Mode::Browse));
}

#[test]
fn submitted_values_queue_in_order_and_remain_owned_when_full() {
    let (commands, incoming) = mpsc::channel();
    let (outgoing, events) = mpsc::channel();
    let mut writer = AsyncWriter {
        commands,
        events,
        rows: None,
        profiles: None,
        approvals: vec![],
        completions: vec![],
        busy: false,
        pending: Default::default(),
        drafts: Default::default(),
        activity: None,
        one_password: true,
        socket: None,
        channel: None,
        decisions: None,
        secret_prompts: vec![],
        secret_activity: None,
    };
    for index in 0..8 {
        assert_eq!(
            writer.write(&format!("value-{index}"), Zeroizing::new(vec![index])),
            Ok(Action::Queued)
        );
    }
    let (_, retained) = writer
        .write("overflow", Zeroizing::new(vec![99]))
        .unwrap_err();
    assert_eq!(retained.as_slice(), &[99]);
    for index in 0..8 {
        match incoming.recv().unwrap() {
            Command::Write { path, value } => {
                assert_eq!(path, format!("value-{index}"));
                assert_eq!(value.as_slice(), &[index]);
            }
            _ => panic!("expected queued write"),
        }
        outgoing
            .send(Event::Completion(Completion::Saved(format!(
                "value-{index}"
            ))))
            .unwrap();
        writer.pump();
        assert_eq!(writer.pending.len(), 7 - index as usize);
        assert_eq!(writer.busy, index != 7);
    }
    assert!(writer.activity().is_none());
}

#[test]
fn stopped_worker_returns_every_accepted_draft_even_with_another_event_sender() {
    let (commands, incoming) = mpsc::channel();
    let (outgoing, events) = mpsc::channel();
    let mut writer = AsyncWriter {
        commands,
        events,
        rows: None,
        profiles: None,
        approvals: vec![],
        completions: vec![],
        busy: false,
        pending: Default::default(),
        drafts: Default::default(),
        activity: None,
        one_password: true,
        socket: None,
        channel: None,
        decisions: None,
        secret_prompts: vec![],
        secret_activity: None,
    };
    for index in 0..3 {
        assert_eq!(
            writer.write(&format!("value-{index}"), Zeroizing::new(vec![index])),
            Ok(Action::Queued)
        );
    }
    drop(incoming);
    // The independent operator channel still owns an event sender in production.
    let guard = WorkerCompletionGuard(outgoing.clone());
    drop(guard);
    writer.pump();
    assert!(!writer.busy);
    assert!(writer.drafts.is_empty());
    assert_eq!(writer.completions.len(), 3);
    for (index, result) in writer.completions.drain(..).enumerate() {
        match result {
            Completion::SaveFailed { path, value, .. } => {
                assert_eq!(path, format!("value-{index}"));
                assert_eq!(value.as_slice(), &[index as u8]);
            }
            _ => panic!("unsaved draft must be returned"),
        }
    }
    writer.pump();
    assert!(writer.completions.is_empty(), "disconnect is reported once");
}

#[test]
fn real_counts_and_wait_phases_keep_queued_save_activity() {
    let (commands, _incoming) = mpsc::channel();
    let (outgoing, events) = mpsc::channel();
    let mut writer = AsyncWriter {
        commands,
        events,
        rows: None,
        profiles: None,
        approvals: vec![],
        completions: vec![],
        busy: false,
        pending: Default::default(),
        drafts: Default::default(),
        activity: None,
        one_password: true,
        socket: None,
        channel: None,
        decisions: None,
        secret_prompts: vec![],
        secret_activity: None,
    };
    assert!(writer.approval(true).is_err());
    assert_eq!(
        writer.write("next", Zeroizing::new(vec![42])),
        Ok(Action::Queued)
    );
    outgoing.send(Event::Progress(0, 12, true, false)).unwrap();
    writer.pump();
    let progress = writer.activity().unwrap();
    assert!(progress.label.contains("0/12"));
    assert!(progress.label.contains("1Password approval"));
    assert!(progress.label.contains("1 saves queued"));
    outgoing.send(Event::Progress(7, 12, false, false)).unwrap();
    writer.pump();
    assert!(writer.activity().unwrap().label.contains("7/12"));
    outgoing
        .send(Event::Phase(
            "Waiting for SSH deployment and target generators",
        ))
        .unwrap();
    writer.pump();
    assert!(writer.activity().unwrap().label.contains("Waiting for SSH"));
    assert_eq!(writer.drafts.len(), 2);
}
