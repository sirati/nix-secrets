use super::BackgroundUpdate;
use crate::client::BackendClient;
use crate::socket::connect_verified;
use crate::tree::{self, Row};
use nix_secrets_core::{BackendEvent, Schema};
use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::Sender;

#[cfg(test)]
use std::time::Duration;

pub(super) fn listen(
    socket: PathBuf,
    schema: Schema,
    sender: &Sender<BackgroundUpdate>,
) -> io::Result<()> {
    // Subscribe before taking a snapshot so changes during startup cannot be
    // lost. A queued event causes another snapshot and cannot stale the view.
    let mut subscription = BackendClient::new(connect_verified(&socket)?);
    subscription.subscribe_changes()?;
    let mut client = BackendClient::new(connect_verified(&socket)?);
    client.register_frontend()?;
    if client.has_pending_approvals()? && sender.send(BackgroundUpdate::ApprovalPending).is_err() {
        return Ok(());
    }
    let mut last_rows = None;
    refresh(&mut client, &schema, &mut last_rows, sender)?;
    loop {
        match subscription.next_change()? {
            BackendEvent::ApprovalRequested { .. } => {
                if sender.send(BackgroundUpdate::ApprovalPending).is_err() {
                    return Ok(());
                }
            }
            BackendEvent::SecretChanged { .. } | BackendEvent::PublicInfoChanged { .. } => {
                refresh(&mut client, &schema, &mut last_rows, sender)?;
            }
        }
    }
}

fn refresh(
    client: &mut BackendClient,
    schema: &Schema,
    last_rows: &mut Option<Vec<Row>>,
    sender: &Sender<BackgroundUpdate>,
) -> io::Result<()> {
    let set = client.list()?.into_keys().collect::<BTreeSet<_>>();
    let public = client
        .list_public_info()?
        .into_keys()
        .collect::<BTreeSet<_>>();
    let rows = tree::rows_with_public(schema, &set, &public);
    if last_rows.as_ref() != Some(&rows) {
        if sender.send(BackgroundUpdate::Rows(rows.clone())).is_err() {
            return Ok(());
        }
        *last_rows = Some(rows);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::Controller;
    use crate::ui::SecretWriter;
    use nix_secrets_core::framing::{read_json, write_json};
    use nix_secrets_core::{Request, Response};
    use nix_secrets_crypto::AgeCommandProvider;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    #[test]
    fn idle_ui_ticks_never_wait_for_backend_io() {
        let (stream, mut server) = UnixStream::pair().unwrap();
        let backend = std::thread::spawn(move || {
            assert!(matches!(
                read_json::<Request>(&mut server).unwrap(),
                Some(Request::RegisterFrontend)
            ));
            write_json(&mut server, &Response::FrontendRegistered).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            let result = read_json::<Request>(&mut server);
            assert!(result.is_err(), "idle UI made a backend request");
        });
        let mut controller = Controller::new(
            BackendClient::new(stream),
            Schema(Default::default()),
            AgeCommandProvider::default(),
            vec![],
        )
        .unwrap();
        let (sender, receiver) = mpsc::channel();
        controller.background = Some(receiver);
        for _ in 0..100 {
            assert!(controller.refresh_rows().unwrap().is_none());
            assert!(controller.poll_approval().unwrap().is_none());
        }
        drop(sender);
        backend.join().unwrap();
    }
}
