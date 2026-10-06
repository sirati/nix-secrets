use super::*;
use crate::artifact_signing::{
    Artifact, DetachedSignature, Manifest, REQUIRED_ROLES, Signatures, SigningRequest,
};
use std::thread;

fn artifact_path() -> String {
    std::fs::canonicalize(
        option_env!("NIX_SECRETS_SIGNING_TEST_ARTIFACT")
            .unwrap_or("/run/current-system/sw/bin/true"),
    )
    .unwrap()
    .to_str()
    .unwrap()
    .into()
}
fn signing_request() -> SigningRequest {
    let path = artifact_path();
    let size = std::fs::metadata(&path).unwrap().len();
    SigningRequest {
        identifier: "ns1.services.nmbl.generation-key".into(),
        host: "ns1".into(),
        public_key_sha256: "a".repeat(64),
        manifest: Manifest {
            artifacts: REQUIRED_ROLES
                .iter()
                .map(|role| Artifact {
                    role: (*role).into(),
                    path: path.clone(),
                    sha512: "b".repeat(128),
                    size,
                })
                .collect(),
        },
    }
}
fn secret_request(id: &str) -> SecretRequest {
    SecretRequest {
        id: id.into(),
        identifiers: vec![],
        reason: Some("sign test generation".into()),
        ssh_signature: None,
        artifact_signature: Some(signing_request()),
        closure_signature: None,
        requester: ProcessInfo::read(std::process::id()),
        parent: None,
        procedure: None,
    }
}
fn signatures(manifest: &Manifest) -> Signatures {
    let mut sidecar = b"NMBLSIG1".to_vec();
    sidecar.resize(3300, 0);
    Signatures {
        signatures: manifest
            .artifacts
            .iter()
            .map(|a| DetachedSignature {
                role: a.role.clone(),
                sha512: a.sha512.clone(),
                size: a.size,
                signature_base64: STANDARD.encode(&sidecar),
            })
            .collect(),
    }
}
fn schema() -> crate::Schema {
    serde_json::from_value(serde_json::json!({"ns1": {"metadata": {"socketPath":"/run/test", "deployment":{"host":"ns1", "destination":"secrets@ns1", "port":22}}, "services":{"nmbl":{"generation-key":{"kind":"operator", "signingOnly":true,"recipientPublicKeys":[],"recipientIds":[]}}}}})).unwrap()
}
fn next_job(jobs: &mpsc::Receiver<Inbox>) -> Job {
    loop {
        match jobs.recv_timeout(Duration::from_secs(2)).unwrap() {
            Inbox::Job(job) => return job,
            Inbox::Step(_) | Inbox::Ended(..) => continue,
            _ => panic!("expected a job"),
        }
    }
}

/// The next frame the TUI end receives, past heartbeats.
fn next_frame(tui: &mut UnixStream) -> Response {
    loop {
        match read_json::<Response>(tui).unwrap().expect("the backend hung up") {
            Response::Heartbeat | Response::ProceduresListed { .. } => continue,
            frame => return frame,
        }
    }
}

fn requested(tui: &mut UnixStream) -> SecretRequest {
    match next_frame(tui) {
        Response::SecretRequested { request } => request,
        other => panic!("expected a request, got {other:?}"),
    }
}

fn answer(tui: &mut UnixStream, request_id: &str, reason: &str) {
    write_json(
        tui,
        &Request::AnswerSecretRequest {
            request_id: request_id.into(),
            answer: SecretAnswer::Denied {
                reason: reason.into(),
            },
        },
    )
    .unwrap();
}

/// Asks for one value as this process, the way `with-secrets` does.
fn ask<'a>(
    operators: &'a Operators,
    requester: Requester<'a>,
) -> Result<SecretAnswer, String> {
    request_operator(
        operators,
        std::process::id(),
        vec!["ns1.services.app.token".into()],
        None,
        None,
        None,
        None,
        requester,
    )
}

fn denial(result: Result<SecretAnswer, String>) -> String {
    match result {
        Ok(SecretAnswer::Denied { reason }) => reason,
        other => panic!("expected the operator's denial, got {other:?}"),
    }
}

#[test]
fn one_channel_carries_several_requests_and_routes_each_answer_by_id_once() {
    let operators = Operators::default();
    let (mut backend, tui) = UnixStream::pair().unwrap();
    tui.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    thread::scope(|scope| {
        // Dropped while a failing test unwinds, so the attached channel ends.
        let mut tui = tui;
        let attached = scope.spawn(|| attach(&mut backend, &operators, 1, std::process::id()));
        assert!(matches!(next_frame(&mut tui), Response::OperatorAttached));
        let first = scope.spawn(|| ask(&operators, Requester::default()));
        let first_request = requested(&mut tui);
        // A second request waits at the same time instead of being refused.
        let second = scope.spawn(|| ask(&operators, Requester::default()));
        let second_request = requested(&mut tui);
        assert_ne!(first_request.id, second_request.id);
        assert_eq!(operators.pending_count(), 2);
        // Made-up ids reach nobody and do not break the channel.
        answer(&mut tui, "secret-made-up", "forged");
        answer(&mut tui, &second_request.id, "second");
        assert_eq!(denial(second.join().unwrap()), "second");
        // A replayed answer to the answered request reaches nobody either.
        answer(&mut tui, &second_request.id, "replayed");
        answer(&mut tui, &first_request.id, "first");
        assert_eq!(denial(first.join().unwrap()), "first");
        assert_eq!(operators.pending_count(), 0);
        // A request whose TUI goes away waits for the next one, which shows
        // it again; the first TUI's countdown is gone with it.
        let third = scope.spawn(|| ask(&operators, Requester::default()));
        let shown = requested(&mut tui);
        tui.shutdown(std::net::Shutdown::Both).unwrap();
        attached.join().unwrap().unwrap();
        assert!(operators.attached.lock().unwrap().is_empty());
        let (mut again, mut next) = UnixStream::pair().unwrap();
        next.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let operators_ref = &operators;
        scope.spawn(move || attach(&mut again, operators_ref, 2, std::process::id()));
        assert!(matches!(next_frame(&mut next), Response::OperatorAttached));
        assert_eq!(requested(&mut next).id, shown.id);
        answer(&mut next, &shown.id, "third");
        assert_eq!(denial(third.join().unwrap()), "third");
        next.shutdown(std::net::Shutdown::Both).unwrap();
    });
}

#[test]
fn waiting_requests_are_bounded() {
    let operators = Operators::default();
    let (sender, jobs) = mpsc::channel();
    operators.attached.lock().unwrap().push((1, sender));
    thread::scope(|scope| {
        let waiting = (0..MAX_PENDING)
            .map(|_| scope.spawn(|| ask(&operators, Requester::default())))
            .collect::<Vec<_>>();
        let jobs = (0..MAX_PENDING).map(|_| next_job(&jobs)).collect::<Vec<_>>();
        let refused = ask(&operators, Requester::default()).unwrap_err();
        assert!(refused.contains("already waiting"), "{refused}");
        for job in jobs {
            let reason = SecretAnswer::Denied { reason: "no".into() };
            job.reply.send(Outcome::Answer(Ok(reason))).unwrap();
        }
        for handle in waiting {
            assert_eq!(denial(handle.join().unwrap()), "no");
        }
        assert_eq!(operators.pending_count(), 0);
    });
}

#[test]
fn a_cancelled_countdown_reaches_the_requester_and_lifts_the_backend_deadline() {
    let deadline = Duration::from_millis(400);
    for cancel in [false, true] {
        let operators =
            Operators::default().with_timing(deadline, Duration::from_millis(100));
        let (mut backend, tui) = UnixStream::pair().unwrap();
        tui.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let (requester, client) = UnixStream::pair().unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        thread::scope(|scope| {
        // Dropped while a failing test unwinds, so the attached channel ends.
        let mut tui = tui;
        let mut client = client;
            scope.spawn(|| attach(&mut backend, &operators, 1, std::process::id()));
            assert!(matches!(next_frame(&mut tui), Response::OperatorAttached));
            let waiting =
                scope.spawn(|| ask(&operators, Requester::new(&requester, None, true)));
            let request = requested(&mut tui);
            assert!(request.countdown());
            if !cancel {
                // Without a cancellation the backend gives up and tells the
                // TUI to drop the prompt.
                let error = waiting.join().unwrap().unwrap_err();
                assert!(error.contains("did not answer in time"), "{error}");
                assert!(matches!(
                    next_frame(&mut tui),
                    Response::SecretRequestWithdrawn { request_id } if request_id == request.id
                ));
                tui.shutdown(std::net::Shutdown::Both).unwrap();
                return;
            }
            write_json(
                &mut tui,
                &Request::CancelCountdown {
                    request_id: request.id.clone(),
                },
            )
            .unwrap();
            // The requester hears about it, then gets heartbeats while it
            // waits well past the old deadline.
            let mut frames = Vec::new();
            loop {
                match read_json::<Response>(&mut client).unwrap() {
                    Some(Response::Heartbeat) => frames.push("heartbeat"),
                    Some(Response::CountdownCancelled) => break,
                    other => panic!("unexpected requester frame {other:?}"),
                }
            }
            std::thread::sleep(deadline * 2);
            assert!(matches!(
                read_json::<Response>(&mut client).unwrap(),
                Some(Response::Heartbeat)
            ));
            answer(&mut tui, &request.id, "decided late");
            assert_eq!(denial(waiting.join().unwrap()), "decided late");
            tui.shutdown(std::net::Shutdown::Both).unwrap();
        });
    }
}

#[test]
fn requesters_without_progress_get_no_interim_frames() {
    let operators =
        Operators::default().with_timing(Duration::from_secs(60), Duration::from_millis(50));
    let (mut backend, tui) = UnixStream::pair().unwrap();
    tui.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (requester, client) = UnixStream::pair().unwrap();
    thread::scope(|scope| {
        // Dropped while a failing test unwinds, so the attached channel ends.
        let mut tui = tui;
        scope.spawn(|| attach(&mut backend, &operators, 1, std::process::id()));
        assert!(matches!(next_frame(&mut tui), Response::OperatorAttached));
        let waiting = scope.spawn(|| ask(&operators, Requester::new(&requester, None, false)));
        let request = requested(&mut tui);
        write_json(
            &mut tui,
            &Request::CancelCountdown {
                request_id: request.id.clone(),
            },
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        // An older requester reads exactly one answer frame.
        assert!(!peer_done(&client), "an interim frame reached a legacy requester");
        answer(&mut tui, &request.id, "done");
        assert_eq!(denial(waiting.join().unwrap()), "done");
        tui.shutdown(std::net::Shutdown::Both).unwrap();
    });
}

#[test]
fn later_steps_of_a_procedure_have_no_deadline() {
    let deadline = Duration::from_millis(300);
    let operators = Operators::default().with_timing(deadline, Duration::from_secs(30));
    let (mut backend, tui) = UnixStream::pair().unwrap();
    tui.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (_, token) = operators
        .procedures
        .begin(std::process::id(), "Update ns1", Some(3))
        .unwrap();
    let (requester, _client) = UnixStream::pair().unwrap();
    thread::scope(|scope| {
        // Dropped while a failing test unwinds, so the attached channel ends.
        let mut tui = tui;
        scope.spawn(|| attach(&mut backend, &operators, 1, std::process::id()));
        assert!(matches!(next_frame(&mut tui), Response::OperatorAttached));
        assert!(matches!(
            next_frame(&mut tui),
            Response::ProcedureUpdate { procedure } if procedure.step == 0
        ));
        // The attach snapshot ends with the ids of the live procedures.
        assert!(matches!(
            read_json::<Response>(&mut tui).unwrap(),
            Some(Response::ProceduresListed { ids }) if ids.len() == 1
        ));
        let (requester, token) = (&requester, token.as_str());
        let operators = &operators;
        let in_procedure = move || Requester::new(requester, Some(token), true);
        let first = scope.spawn(move || ask(operators, in_procedure()));
        assert!(matches!(
            next_frame(&mut tui),
            Response::ProcedureUpdate { procedure } if procedure.step == 1
        ));
        let request = requested(&mut tui);
        let step = request.procedure.clone().unwrap();
        assert_eq!((step.step, step.title.as_str()), (1, "Update ns1"));
        assert_eq!(step.label, "release 1 secret value");
        assert!(request.countdown());
        answer(&mut tui, &request.id, "one");
        assert_eq!(denial(first.join().unwrap()), "one");
        let second = scope.spawn(move || ask(operators, in_procedure()));
        next_frame(&mut tui);
        let request = requested(&mut tui);
        assert_eq!(request.procedure.as_ref().unwrap().position(), "step 2/3");
        assert!(!request.countdown());
        // Well past the deadline of a first step, it still waits.
        std::thread::sleep(deadline * 3);
        answer(&mut tui, &request.id, "two");
        assert_eq!(denial(second.join().unwrap()), "two");
        tui.shutdown(std::net::Shutdown::Both).unwrap();
    });
}

#[test]
fn signing_only_key_export_is_rejected_without_operator_request() {
    let (mut backend, mut requester) = UnixStream::pair().unwrap();
    let operators = Operators::default();
    let (sender, jobs) = mpsc::channel();
    operators.attached.lock().unwrap().push((1, sender));
    request(
        &mut backend,
        &operators,
        std::process::id(),
        vec!["ns1.services.nmbl.generation-key".into()],
        None,
        None,
        false,
        &schema(),
    )
    .unwrap();
    let Some(Response::Error { message }) = read_json(&mut requester).unwrap() else {
        panic!("expected refusal");
    };
    assert!(message.contains("plaintext export is forbidden"));
    assert!(matches!(jobs.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert!(operators.pending_count() == 0);
}
#[test]
fn chunks_are_bounded_exact_and_scoped_to_pending_request() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("artifact");
    let bytes = (0..crate::artifact_signing::CHUNK_BYTES + 17)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&path, &bytes).unwrap();
    let operators = Operators::default();
    operators.artifacts.lock().unwrap().insert(
        "pending".into(),
        BTreeMap::from([(
            "generation-image".into(),
            std::fs::File::open(path).unwrap(),
        )]),
    );
    for offset in [
        0,
        crate::artifact_signing::CHUNK_BYTES as u64,
        bytes.len() as u64 - 1,
    ] {
        let Response::SigningArtifactChunk {
            offset: actual,
            bytes_base64,
        } = read_artifact(&operators, "pending", "generation-image", offset).unwrap()
        else {
            panic!("chunk");
        };
        let chunk = STANDARD.decode(bytes_base64).unwrap();
        assert_eq!(actual, offset);
        assert!(chunk.len() <= crate::artifact_signing::CHUNK_BYTES);
        assert_eq!(
            chunk,
            bytes[offset as usize
                ..bytes
                    .len()
                    .min(offset as usize + crate::artifact_signing::CHUNK_BYTES)]
        );
    }
    for (id, role, offset) in [
        ("stale", "generation-image", 0),
        ("pending", "unknown", 0),
        ("pending", "generation-image", bytes.len() as u64),
        ("pending", "generation-image", u64::MAX),
    ] {
        assert!(read_artifact(&operators, id, role, offset).is_err());
    }
    operators.artifacts.lock().unwrap().remove("pending");
    assert!(read_artifact(&operators, "pending", "generation-image", 0).is_err());
}
#[test]
fn artifact_registry_cleans_on_answer_operator_loss_and_requester_disconnect() {
    for mode in ["answer", "operator-loss", "requester-disconnect"] {
        let operators = Operators::default();
        let (sender, jobs) = mpsc::channel();
        operators.attached.lock().unwrap().push((1, sender));
        let (requester, peer) = UnixStream::pair().unwrap();
        thread::scope(|scope| {
            let handle = scope.spawn(|| {
                request_operator(
                    &operators,
                    std::process::id(),
                    vec![],
                    None,
                    None,
                    Some(signing_request()),
                    None,
                    Requester { stream: Some(&requester), ..Default::default() },
                )
            });
            let job = next_job(&jobs);
            assert!(read_artifact(&operators, &job.request.id, "generation-image", 0).is_ok());
            let id = job.request.id.clone();
            let held = match mode {
                "answer" => {
                    job.reply.send(Outcome::Answer(Ok(SecretAnswer::ArtifactsSigned {
                            signatures: signatures(
                                job.request
                                    .artifact_signature
                                    .as_ref()
                                    .map(|r| &r.manifest)
                                    .unwrap(),
                            ),
                        })))
                        .unwrap();
                    None
                }
                "operator-loss" => {
                    // The request waits for another TUI until its
                    // requester gives up.
                    operators.attached.lock().unwrap().clear();
                    drop(job);
                    drop(peer);
                    None
                }
                _ => {
                    drop(peer);
                    Some(job)
                }
            };
            let result = handle.join().unwrap();
            assert_eq!(result.is_ok(), mode == "answer");
            if mode == "requester-disconnect" {
                assert!(result.unwrap_err().contains("requester disconnected"));
            }
            drop(held);
            assert!(operators.artifacts.lock().unwrap().is_empty());
            assert!(operators.pending_count() == 0);
            assert!(read_artifact(&operators, &id, "generation-image", 0).is_err());
        });
    }
}
#[test]
fn signing_manifest_and_reply_reject_role_digest_size_and_host_tampering() {
    let req = signing_request();
    req.validate().unwrap();
    let reply = signatures(&req.manifest);
    reply.validate(&req.manifest).unwrap();
    for kind in ["duplicate", "unknown", "digest", "size", "missing", "host"] {
        let mut changed = req.clone();
        match kind {
            "duplicate" => {
                changed.manifest.artifacts[1].role = changed.manifest.artifacts[0].role.clone()
            }
            "unknown" => changed.manifest.artifacts[0].role = "unasked".into(),
            "digest" => changed.manifest.artifacts[0].sha512 = "C".repeat(128),
            "size" => changed.manifest.artifacts[0].size = 0,
            "missing" => {
                changed.manifest.artifacts.pop();
            }
            _ => changed.host = "other-host".into(),
        }
        assert!(changed.validate().is_err(), "{kind}");
    }
    for kind in ["digest", "size", "role", "duplicate", "missing", "extra"] {
        let mut changed = reply.clone();
        match kind {
            "digest" => changed.signatures[0].sha512 = "c".repeat(128),
            "size" => changed.signatures[0].size += 1,
            "role" => changed.signatures[0].role = "unasked".into(),
            "duplicate" => changed.signatures[1] = changed.signatures[0].clone(),
            "missing" => {
                changed.signatures.pop();
            }
            _ => changed.signatures.push(changed.signatures[0].clone()),
        }
        assert!(changed.validate(&req.manifest).is_err(), "{kind}");
    }
}

#[test]
fn signing_manifest_accepts_optional_network_stage_and_rescue_tools_once() {
    let base = signing_request();
    let optional = |role: &str| Artifact {
        role: role.into(),
        ..base.manifest.artifacts[0].clone()
    };
    for roles in [
        &["network-stage"][..],
        &["rescue-tools"],
        &["network-stage", "rescue-tools"],
    ] {
        let mut req = base.clone();
        req.manifest
            .artifacts
            .extend(roles.iter().map(|role| optional(role)));
        req.validate().unwrap();
        signatures(&req.manifest).validate(&req.manifest).unwrap();
    }
    let mut duplicate = base.clone();
    duplicate.manifest.artifacts.extend([
        optional("rescue-tools"),
        optional("rescue-tools"),
    ]);
    assert!(duplicate.validate().is_err());
    let mut eight = base.clone();
    eight.manifest.artifacts.extend([
        optional("network-stage"),
        optional("rescue-tools"),
        optional("driver-image"),
    ]);
    assert!(eight.validate().is_err());
    // An optional role never stands in for a required one.
    let mut replaced = base.clone();
    replaced.manifest.artifacts[4] = optional("rescue-tools");
    assert!(replaced.validate().is_err());
}

#[test]
fn artifact_request_returns_only_signatures_and_rejects_plaintext_answers() {
    for mode in ["signatures", "plaintext", "ssh-signature", "deny"] {
        let operators = Operators::default();
        let (sender, jobs) = mpsc::channel();
        operators.attached.lock().unwrap().push((1, sender));
        let (mut backend, mut client) = UnixStream::pair().unwrap();
        thread::scope(|scope| {
            let handle = scope.spawn(|| {
                request_artifacts(
                    &mut backend,
                    &operators,
                    std::process::id(),
                    signing_request(),
                    Some("test reason".into()),
                    None,
                    false,
                    &schema(),
                )
            });
            let job = next_job(&jobs);
            let answer = match mode {
                "signatures" => SecretAnswer::ArtifactsSigned {
                    signatures: signatures(&job.request.artifact_signature.unwrap().manifest),
                },
                "plaintext" => SecretAnswer::Approved { values: vec![] },
                "ssh-signature" => SecretAnswer::Signed {
                    reply: vec![1, 2, 3],
                },
                _ => SecretAnswer::Denied {
                    reason: "operator denied".into(),
                },
            };
            job.reply.send(Outcome::Answer(Ok(answer))).unwrap();
            handle.join().unwrap().unwrap();
            match read_json::<Response>(&mut client).unwrap().unwrap() {
                Response::ArtifactSignatures { signatures: reply } if mode == "signatures" => {
                    reply.validate(&signing_request().manifest).unwrap()
                }
                Response::Error { message } if mode != "signatures" => {
                    assert!(message.contains(if mode == "deny" {
                        "operator denied"
                    } else {
                        "unasked"
                    }))
                }
                _ => panic!("backend returned an unexpected answer"),
            }
            assert!(operators.artifacts.lock().unwrap().is_empty());
            assert!(operators.pending_count() == 0);
        });
    }
}

fn closure_request() -> crate::closure_signing::SigningRequest {
    crate::closure_signing::SigningRequest {
        identifier: "ns1.services.nmbl.generation-key".into(),
        host: "ns1".into(),
        public_key_sha256: "a".repeat(64),
        manifest: crate::closure_signing::Manifest {
            version: 1,
            paths: vec![crate::closure_signing::ManifestPath {
                path: format!("/nix/store/{}-root", "0".repeat(32)),
                nar_hash: format!("sha256:{}", "0".repeat(52)),
                nar_size: 1,
                references: vec![],
            }],
        },
    }
}

#[test]
fn closure_metadata_registry_liveness_owner_denial_disconnect_and_no_replay() {
    for disconnected in [false, true] {
        let operators = Operators::default();
        let (sender, jobs) = mpsc::channel();
        operators.attached.lock().unwrap().push((1, sender));
        operators
            .operator_peers
            .lock()
            .unwrap()
            .insert(1, std::process::id());
        let (requester, peer) = UnixStream::pair().unwrap();
        thread::scope(|scope| {
            let handle = scope.spawn(|| {
                request_operator(
                    &operators,
                    std::process::id(),
                    vec![],
                    None,
                    None,
                    None,
                    Some(closure_request()),
                    Requester { stream: Some(&requester), ..Default::default() },
                )
            });
            let job = next_job(&jobs);
            let id = job.request.id.clone();
            assert!(job.request.artifact_signature.is_none());
            assert!(operators.artifacts.lock().unwrap().is_empty());
            assert!(check_closure(&operators, &id, std::process::id()).is_ok());
            assert!(check_closure(&operators, &id, std::process::id() + 1).is_err());
            assert!(check_closure(&operators, "unknown", std::process::id()).is_err());
            if disconnected {
                // Parallel tests can briefly inherit this descriptor across
                // fork before exec; shutdown closes the connection itself.
                peer.shutdown(std::net::Shutdown::Both).unwrap();
                drop(peer);
                assert!(check_closure(&operators, &id, std::process::id()).is_err());
                assert!(
                    handle
                        .join()
                        .unwrap()
                        .unwrap_err()
                        .contains("requester disconnected")
                );
            } else {
                job.reply.send(Outcome::Answer(Ok(SecretAnswer::Denied {
                        reason: "operator denied".into(),
                    })))
                    .unwrap();
                assert!(matches!(
                    handle.join().unwrap().unwrap(),
                    SecretAnswer::Denied { .. }
                ));
            }
            assert!(operators.closure_requests.lock().unwrap().is_empty());
            assert!(check_closure(&operators, &id, std::process::id()).is_err());
            assert!(operators.pending_count() == 0);
        });
    }
}

#[test]
fn closure_protocol_returns_signatures_only_and_rejects_other_answers() {
    let request = closure_request();
    let signatures = crate::closure_signing::Signatures {
        version: 1,
        signatures: vec![crate::closure_signing::PathSignature {
            path: request.manifest.paths[0].path.clone(),
            signature: format!("cache:{}", STANDARD.encode([0u8; 64])),
        }],
    };
    let answer = SecretAnswer::ClosureSigned {
        signatures: signatures.clone(),
    };
    let wire = serde_json::to_vec(&answer).unwrap();
    let decoded: SecretAnswer = serde_json::from_slice(&wire).unwrap();
    assert_eq!(
        closure_answer(decoded, &request.manifest).unwrap(),
        signatures
    );
    assert!(
        closure_answer(SecretAnswer::Approved { values: vec![] }, &request.manifest)
            .unwrap_err()
            .contains("unasked")
    );
    assert!(
        closure_answer(SecretAnswer::Signed { reply: vec![] }, &request.manifest)
            .unwrap_err()
            .contains("unasked")
    );
    assert!(
        closure_answer(
            SecretAnswer::ArtifactsSigned {
                signatures: super::tests::signatures(&signing_request().manifest)
            },
            &request.manifest
        )
        .unwrap_err()
        .contains("unasked")
    );
    assert_eq!(
        closure_answer(
            SecretAnswer::Denied {
                reason: "denied".into()
            },
            &request.manifest
        )
        .unwrap_err(),
        "denied"
    );
    assert!(serde_json::from_slice::<SecretAnswer>(br#"{"answer":"closure-signed","signatures":{"version":1,"signatures":[]},"values":[]}"#).is_err());
}

#[test]
fn without_a_tui_a_request_waits_and_its_countdown_starts_when_one_attaches() {
    let deadline = Duration::from_millis(400);
    let operators = Operators::default().with_timing(deadline, Duration::from_millis(100));
    let (requester, client) = UnixStream::pair().unwrap();
    let (mut backend, tui) = UnixStream::pair().unwrap();
    thread::scope(|scope| {
        let mut tui = tui;
        let mut client = client;
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tui.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let waiting = scope.spawn(|| ask(&operators, Requester::new(&requester, None, true)));
        // The requester hears that it waits for a TUI, then heartbeats.
        assert!(matches!(
            read_json::<Response>(&mut client).unwrap(),
            Some(Response::WaitingForOperator)
        ));
        // Far longer than the deadline of a shown request.
        std::thread::sleep(deadline * 3);
        assert!(matches!(
            read_json::<Response>(&mut client).unwrap(),
            Some(Response::Heartbeat)
        ));
        scope.spawn(|| attach(&mut backend, &operators, 1, std::process::id()));
        assert!(matches!(next_frame(&mut tui), Response::OperatorAttached));
        let request = requested(&mut tui);
        // Answered within the deadline counted from now.
        std::thread::sleep(deadline / 4);
        answer(&mut tui, &request.id, "seen");
        assert_eq!(denial(waiting.join().unwrap()), "seen");
        tui.shutdown(std::net::Shutdown::Both).unwrap();
    });
}
