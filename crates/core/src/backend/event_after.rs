use super::{BackendEvent, Request};
use crate::Schema;

pub(super) fn event_after_success(request: &Request, schema: &Schema) -> Option<BackendEvent> {
    match request {
        Request::Set { path, .. } | Request::SetIfVersion { path, .. } => {
            Some(BackendEvent::SecretChanged {
                path: path.to_string(),
                set: true,
            })
        }
        Request::Remove { path } | Request::RemoveIfVersion { path, .. } => {
            Some(BackendEvent::SecretChanged {
                path: path.to_string(),
                set: false,
            })
        }
        Request::SetPublicInfoIfVersion { path, .. }
        | Request::RemovePublicInfoIfVersion { path, .. } => {
            let crate::schema::LeafSpec::Stored(spec) = schema.leaf(path).ok()? else {
                return None;
            };
            Some(BackendEvent::PublicInfoChanged {
                shared_id: spec.shared_public_id.clone()?,
                set: matches!(request, Request::SetPublicInfoIfVersion { .. }),
            })
        }
        Request::SubmitApproval { request } => Some(BackendEvent::ApprovalRequested {
            request: request.clone(),
        }),
        Request::SaveProfile { .. } | Request::DeleteProfile { .. } => {
            Some(BackendEvent::ProfilesChanged)
        }
        _ => None,
    }
}
