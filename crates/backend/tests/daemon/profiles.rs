use super::*;
use nix_secrets_core::{BackendEvent, ProfileViewFilter, ViewProfile};
#[test]
fn profile_rpc_persists_across_backend_restart_and_notifies_other_clients() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("backend.sock");
    let manifest_path = directory.path().join("manifest.json");
    fs::write(&manifest_path, manifest(&socket)).unwrap();
    let mut backend = start(directory.path(), &socket, Some(&manifest_path), None);
    if !await_socket(&mut backend, &socket) {
        return;
    }
    let mut subscriber = UnixStream::connect(&socket).unwrap();
    subscriber
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert!(matches!(
        call(&mut subscriber, Request::SubscribeChanges),
        Response::Subscribed
    ));
    let mut client = UnixStream::connect(&socket).unwrap();
    let initial = match call(&mut client, Request::ListProfiles) {
        Response::Profiles { snapshot } => snapshot,
        other => panic!("unexpected profile response: {other:?}"),
    };
    let profile = ViewProfile {
        tree_order: vec!["host".into(), "namespace".into(), "name".into()],
        facets: Default::default(),
        view_filter: ProfileViewFilter::All,
        human_only: true,
    };
    let saved = match call(
        &mut client,
        Request::SaveProfile {
            name: "Laptop".into(),
            profile: profile.clone(),
            expected_revision: initial.revision,
        },
    ) {
        Response::Profiles { snapshot } => snapshot,
        other => panic!("unexpected save response: {other:?}"),
    };
    assert_eq!(saved.profiles["Laptop"], profile);
    assert!(matches!(
        read_json(&mut subscriber).unwrap(),
        Some(Response::Change {
            update: BackendEvent::ProfilesChanged
        })
    ));
    assert!(matches!(
        call(
            &mut client,
            Request::SaveProfile {
                name: "Stale".into(),
                profile,
                expected_revision: initial.revision,
            }
        ),
        Response::Error { .. }
    ));
    backend.kill().unwrap();
    backend.wait().unwrap();
    let mut reopened = start(directory.path(), &socket, Some(&manifest_path), None);
    assert!(await_socket(&mut reopened, &socket));
    let mut client = UnixStream::connect(&socket).unwrap();
    match call(&mut client, Request::ListProfiles) {
        Response::Profiles { snapshot } => assert_eq!(snapshot, saved),
        other => panic!("unexpected reopened response: {other:?}"),
    }
    reopened.kill().unwrap();
    reopened.wait().unwrap();
}
