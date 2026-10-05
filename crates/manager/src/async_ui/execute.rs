use super::*;
pub(super) fn execute(controller: &mut Controller, command: Command) -> Completion {
    match command {
        Command::Write { path, value } => match controller.write(&path, value) {
            Ok(Action::Saved(path)) => Completion::Saved(path),
            Ok(_) => Completion::Failed("save did not complete".into()),
            Err((message, value)) => Completion::SaveFailed {
                path,
                value,
                message,
            },
        },
        Command::Delete(path) => match controller.delete(&path) {
            Ok(()) => Completion::Deleted(path),
            Err(error) => Completion::Failed(error),
        },
        Command::Reveal(path) => match controller.reveal(&path) {
            Ok(value) => Completion::Revealed { path, value },
            Err(error) => Completion::Failed(error),
        },
        Command::CopyPublic(path) => match controller.copy_public(&path) {
            Ok(()) => Completion::Copied(format!("copied public key for {path}")),
            Err(error) => Completion::Failed(error),
        },
        Command::CopyValue(value) => match controller.copy(&value) {
            Ok(()) => Completion::Copied("value copied".into()),
            Err(error) => Completion::Failed(error),
        },
        Command::Generate {
            path,
            kind,
            replacing,
        } => match controller.generate(&path, kind) {
            Ok(value) => Completion::Generated {
                path,
                value,
                replacing,
            },
            Err(error) => Completion::Failed(error),
        },
        Command::BulkGenerate { .. } => unreachable!("bulk execution emits progress"),
        Command::GenerateKeypair(path) => match controller.generate_keypair(&path) {
            Ok(()) => Completion::KeypairGenerated(path),
            Err(error) => Completion::Failed(error),
        },
        Command::Approval(accepted) => {
            let result = controller.approval(accepted);
            approval_done(controller, accepted, result)
        }
        Command::ApprovalWith(accepted, unchecked) => {
            let result = controller.approval_with(accepted, &unchecked);
            approval_done(controller, accepted, result)
        }
        Command::HostMutations(accepted, token) => {
            let result = controller.approve_host_mutations(accepted, &token);
            match result {
                Ok(None) if !accepted => Completion::HostMutationsDeclined,
                other => approval_done(controller, accepted, other),
            }
        }
        Command::SaveProfile {
            name,
            profile,
            revision,
        } => match controller.save_profile(name.clone(), profile, revision) {
            Ok(snapshot) => Completion::ProfileSaved { name, snapshot },
            Err(error) => Completion::Failed(error),
        },
        Command::CommitSummary => match controller.commit_summary() {
            Ok(summary) => Completion::CommitSummary(summary),
            Err(error) => Completion::Failed(error),
        },
        Command::Commit(options) => match controller.commit(options) {
            Ok(result) => Completion::Committed(result),
            Err(error) => Completion::CommitFailed(error),
        },
        Command::RequestDeployment(host) => match controller.request_deployment(&host) {
            Ok(()) => Completion::DeploymentRequested(host),
            Err(error) => Completion::Failed(error),
        },
        Command::DeleteProfile { name, revision } => {
            match controller.delete_profile(name.clone(), revision) {
                Ok(snapshot) => Completion::ProfileDeleted { name, snapshot },
                Err(error) => Completion::Failed(error),
            }
        }
    }
}

fn approval_done(
    controller: &mut Controller,
    accepted: bool,
    result: Result<Option<ApprovalRequest>, String>,
) -> Completion {
    match result {
        Ok(None) if accepted => Completion::Deployed {
            generated: controller.take_generated(),
            skipped: controller.take_skipped(),
            summary: controller.take_summary(),
        },
        Ok(next) => Completion::ApprovalDone(next.map(Box::new)),
        // A failed deployment is final; the dialog closes.
        Err(error) => Completion::ApprovalLost(error),
    }
}
