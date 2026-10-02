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
#[test]
fn unix_transport_accepts_bound_signature_and_explicit_denial() {
    for denied in [false, true] {
        let (mut backend, mut tui) = UnixStream::pair().unwrap();
        let req = secret_request("unique-request");
        let handle =
            thread::spawn(move || ask_with_timeout(&mut backend, &req, Duration::from_secs(2)));
        let Some(Response::SecretRequested { request }) = read_json(&mut tui).unwrap() else {
            panic!("expected request");
        };
        let answer = if denied {
            SecretAnswer::Denied {
                reason: "operator refused".into(),
            }
        } else {
            SecretAnswer::ArtifactsSigned {
                signatures: signatures(&request.artifact_signature.unwrap().manifest),
            }
        };
        write_json(
            &mut tui,
            &Request::AnswerSecretRequest {
                request_id: request.id,
                answer,
            },
        )
        .unwrap();
        match handle.join().unwrap().unwrap() {
            SecretAnswer::Denied { reason } if denied => assert_eq!(reason, "operator refused"),
            SecretAnswer::ArtifactsSigned { signatures: reply } if !denied => {
                reply.validate(&signing_request().manifest).unwrap()
            }
            _ => panic!("unasked answer"),
        }
    }
}
#[test]
fn unix_transport_rejects_wrong_id_replay_disconnect_and_timeout() {
    for mode in ["wrong-id", "replay", "disconnect", "timeout"] {
        let (mut backend, mut tui) = UnixStream::pair().unwrap();
        let req = secret_request("current-request");
        let handle =
            thread::spawn(move || ask_with_timeout(&mut backend, &req, Duration::from_millis(60)));
        let _: Option<Response> = read_json(&mut tui).unwrap();
        if mode == "wrong-id" || mode == "replay" {
            write_json(
                &mut tui,
                &Request::AnswerSecretRequest {
                    request_id: if mode == "replay" {
                        "previous-request"
                    } else {
                        "unrelated-request"
                    }
                    .into(),
                    answer: SecretAnswer::Denied {
                        reason: "no".into(),
                    },
                },
            )
            .unwrap();
        }
        if mode == "disconnect" {
            drop(tui);
        }
        let error = handle.join().unwrap().unwrap_err();
        match mode {
            "wrong-id" | "replay" => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
            "disconnect" => assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof),
            _ => assert!(matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            )),
        }
    }
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
        &schema(),
    )
    .unwrap();
    let Some(Response::Error { message }) = read_json(&mut requester).unwrap() else {
        panic!("expected refusal");
    };
    assert!(message.contains("plaintext export is forbidden"));
    assert!(matches!(jobs.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert!(!operators.pending.load(Ordering::SeqCst));
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
                    Some(&requester),
                )
            });
            let job = jobs.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(read_artifact(&operators, &job.request.id, "generation-image", 0).is_ok());
            let id = job.request.id.clone();
            let held = match mode {
                "answer" => {
                    job.reply
                        .send(Ok(SecretAnswer::ArtifactsSigned {
                            signatures: signatures(
                                job.request
                                    .artifact_signature
                                    .as_ref()
                                    .map(|r| &r.manifest)
                                    .unwrap(),
                            ),
                        }))
                        .unwrap();
                    None
                }
                "operator-loss" => {
                    drop(job);
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
            assert!(!operators.pending.load(Ordering::SeqCst));
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
                    &schema(),
                )
            });
            let job = jobs.recv_timeout(Duration::from_secs(2)).unwrap();
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
            job.reply.send(Ok(answer)).unwrap();
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
            assert!(!operators.pending.load(Ordering::SeqCst));
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
                    Some(&requester),
                )
            });
            let job = jobs.recv_timeout(Duration::from_secs(2)).unwrap();
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
                job.reply
                    .send(Ok(SecretAnswer::Denied {
                        reason: "operator denied".into(),
                    }))
                    .unwrap();
                assert!(matches!(
                    handle.join().unwrap().unwrap(),
                    SecretAnswer::Denied { .. }
                ));
            }
            assert!(operators.closure_requests.lock().unwrap().is_empty());
            assert!(check_closure(&operators, &id, std::process::id()).is_err());
            assert!(!operators.pending.load(Ordering::SeqCst));
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
