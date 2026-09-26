//! `D`: asks the backend to deploy a host. The request comes back as an
//! ordinary approval, so it takes the same path as one from `nix-secrets
//! deploy`: host-key check, the create/replace/generate/derive dialog, the
//! missing-values refusal, then the deployment.
use super::*;

pub(super) fn reduce(
    model: &mut Model,
    writer: &mut impl SecretWriter,
    selected: usize,
    event: UiEvent,
) {
    let hosts = model.deploy_hosts();
    let last = hosts.len().saturating_sub(1);
    match event {
        UiEvent::Up => {
            model.mode = Mode::DeployHost {
                selected: selected.saturating_sub(1),
            }
        }
        UiEvent::Down => {
            model.mode = Mode::DeployHost {
                selected: (selected + 1).min(last),
            }
        }
        UiEvent::Enter | UiEvent::Character('y') => match hosts.get(selected) {
            Some(host) => match writer.request_deployment(host) {
                Ok(()) => {}
                Err(error) => fail_unless_queued(model, error),
            },
            None => model.inform("the evaluated schema has no hosts to deploy"),
        },
        UiEvent::Escape | UiEvent::Character('n') => {}
        _ => model.mode = Mode::DeployHost { selected },
    }
}
