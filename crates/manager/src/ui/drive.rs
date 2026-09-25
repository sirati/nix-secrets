use super::*;
use std::time::{Duration, Instant};

pub fn drive(
    frontend: &mut impl Frontend,
    writer: &mut impl SecretWriter,
    model: &mut Model,
) -> io::Result<()> {
    let mut redraw_at = Some(Instant::now());
    loop {
        let now = Instant::now();
        if redraw_at.is_some_and(|at| now >= at) {
            frontend.draw(model)?;
            redraw_at = None;
        }
        let timeout = redraw_at
            .map(|at| at.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_millis(50));
        let event = frontend.read(timeout)?;
        if event == UiEvent::Tick {
            while let Some(completion) = writer.poll_completion() {
                apply_completion(model, completion);
                schedule(&mut redraw_at);
            }
            let activity = writer.activity();
            if activity.is_some() || model.activity.is_some() {
                // Keeps the spinner and elapsed time moving.
                schedule(&mut redraw_at);
            }
            model.activity = activity;
            match writer.refresh_profiles() {
                Ok(Some(snapshot)) => {
                    model.profiles = snapshot;
                    schedule(&mut redraw_at);
                }
                Ok(None) => {}
                Err(error) => {
                    model.fail(error);
                    schedule(&mut redraw_at);
                }
            }
            if matches!(model.mode, Mode::Browse) {
                match writer.refresh_rows() {
                    Ok(Some(rows)) => {
                        model.update_rows(rows);
                        schedule(&mut redraw_at);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        model.fail(error);
                        schedule(&mut redraw_at);
                    }
                }
            }
            match writer.poll_approval() {
                Ok(Some(request)) => {
                    model.offer_approval(request);
                    schedule(&mut redraw_at);
                }
                Ok(None) => {}
                Err(message) => {
                    if matches!(model.mode, Mode::Approval(_)) {
                        model.mode = Mode::Browse;
                    }
                    model.fail(message);
                    schedule(&mut redraw_at);
                }
            }
            continue;
        }
        if matches!(&event, UiEvent::Hover(target) if model.hover == *target) {
            continue;
        }
        let action = reduce(model, event, writer);
        model.show_pending_approval();
        schedule(&mut redraw_at);
        if action == Action::Quit {
            return Ok(());
        }
    }
}

fn schedule(redraw_at: &mut Option<Instant>) {
    schedule_at(redraw_at, Instant::now());
}

fn schedule_at(redraw_at: &mut Option<Instant>, now: Instant) {
    // A burst never moves the first input's deadline. This batches terminal
    // writes while keeping the input-to-redraw target at 30 ms.
    redraw_at.get_or_insert(now + Duration::from_millis(30));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_keys_never_extend_the_first_keys_redraw_deadline() {
        let first_key = Instant::now();
        let mut deadline = None;
        for offset in [0, 10, 20, 29] {
            schedule_at(&mut deadline, first_key + Duration::from_millis(offset));
        }
        assert_eq!(deadline, Some(first_key + Duration::from_millis(30)));
        assert!(deadline.unwrap().duration_since(first_key) <= Duration::from_millis(33));
    }
}

fn apply_completion(model: &mut Model, completion: Completion) {
    match completion {
        Completion::Saved(path) => {
            set_row(model, &path, true);
            model.inform(format!("saved {path}"));
        }
        Completion::SaveFailed {
            path,
            value,
            message,
        } => {
            let dialog = Mode::ProviderFailure {
                message,
                path,
                value,
            };
            if matches!(model.mode, Mode::Browse) {
                model.mode = dialog;
            } else {
                model.pending_dialogs.push_back(dialog);
            }
        }
        Completion::Deleted(path) => {
            set_row(model, &path, false);
            model.inform(format!("deleted {path}"));
        }
        Completion::Revealed { path, value } => {
            let selected =
                model.selected().and_then(|row| row.path.as_deref()) == Some(path.as_str());
            match std::mem::replace(&mut model.mode, Mode::Browse) {
                Mode::Browse if selected => {
                    model.mode = Mode::Reveal {
                        path,
                        value,
                        scroll: 0,
                        underneath: None,
                    }
                }
                // Requested from an entry or replace dialog for the same value:
                // show it over that dialog, which closing the reveal restores.
                dialog @ (Mode::Edit { .. } | Mode::Replace { .. })
                    if dialog_path(&dialog) == Some(path.as_str()) =>
                {
                    model.mode = Mode::Reveal {
                        path,
                        value,
                        scroll: 0,
                        underneath: Some(Box::new(dialog)),
                    }
                }
                other => model.mode = other,
            }
        }
        Completion::Copied(message) => model.inform(message),
        Completion::Failed(message) => model.fail(message),
        Completion::Generated {
            path,
            value,
            replacing,
        } => {
            if matches!(model.mode, Mode::Browse)
                && model.selected().and_then(|row| row.path.as_deref()) == Some(path.as_str())
            {
                model.mode = Mode::GeneratedPreview {
                    path,
                    value,
                    revealed: false,
                    replacing,
                };
            }
        }
        Completion::BulkGenerated { saved, failed } => {
            if matches!(model.mode, Mode::BulkProgress { .. }) {
                model.mode = Mode::Browse;
            }
            if failed.is_empty() {
                model.inform(format!("Generated and saved {saved} missing passwords."));
            } else {
                model.fail(format!(
                    "Generated and saved {saved} missing passwords. {} failed:\n{}",
                    failed.len(),
                    failed.join("\n")
                ));
            }
        }
        Completion::BulkProgress { done, total } => {
            if matches!(model.mode, Mode::BulkProgress { .. }) {
                model.mode = Mode::BulkProgress { done, total };
            }
        }
        Completion::ApprovalDone(Some(request)) => {
            if matches!(model.mode, Mode::Approval(_)) {
                model.mode = Mode::Browse;
            }
            model.offer_approval(request);
        }
        Completion::ApprovalDone(None) => {
            if matches!(model.mode, Mode::Approval(_)) {
                model.mode = Mode::Browse;
            }
            model.inform("deployment request finished");
        }
        Completion::ApprovalLost(message) => {
            if matches!(model.mode, Mode::Approval(_)) {
                model.mode = Mode::Browse;
            }
            model.fail(message);
        }
        Completion::ProfileSaved { name, snapshot } => {
            model.profiles = snapshot;
            model.active_profile = Some(name.clone());
            model.inform(format!("saved view profile {name}"));
        }
        Completion::ProfileDeleted { name, snapshot } => {
            model.profiles = snapshot;
            if model.active_profile.as_deref() == Some(name.as_str()) {
                model.active_profile = None;
            }
            model.inform(format!("deleted view profile {name}"));
        }
    }
    model.show_pending_approval();
}

fn set_row(model: &mut Model, path: &str, set: bool) {
    if let Some(row) = model
        .rows
        .iter_mut()
        .find(|row| row.path.as_deref() == Some(path))
    {
        row.is_set = set;
    }
}

#[cfg(test)]
pub(crate) fn apply_completion_for_tests(model: &mut Model, completion: Completion) {
    apply_completion(model, completion);
}

fn dialog_path(mode: &Mode) -> Option<&str> {
    match mode {
        Mode::Edit { path, .. } | Mode::Replace { path, .. } => Some(path),
        _ => None,
    }
}
