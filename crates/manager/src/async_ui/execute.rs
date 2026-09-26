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
        Command::Approval(accepted) => match controller.approval(accepted) {
            Ok(None) if accepted => Completion::Deployed {
                generated: controller.take_generated(),
            },
            Ok(next) => Completion::ApprovalDone(next),
            Err(error) => Completion::Failed(error),
        },
        Command::SaveProfile {
            name,
            profile,
            revision,
        } => match controller.save_profile(name.clone(), profile, revision) {
            Ok(snapshot) => Completion::ProfileSaved { name, snapshot },
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
