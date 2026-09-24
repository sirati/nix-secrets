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
            if matches!(model.mode, Mode::Browse) {
                match writer.refresh_rows() {
                    Ok(Some(rows)) => {
                        model.update_rows(rows);
                        schedule(&mut redraw_at);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        model.message = Some(error);
                        model.message_since = Some(Instant::now());
                        schedule(&mut redraw_at);
                    }
                }
            }
            if matches!(model.mode, Mode::Browse)
                && model
                    .message_since
                    .is_some_and(|since| since.elapsed() >= Duration::from_secs(5))
            {
                model.message = None;
                model.message_since = None;
                schedule(&mut redraw_at);
            }
            match writer.poll_approval() {
                Ok(Some(request)) => {
                    model.apply_task_status(&request);
                    model.mode = Mode::Approval(request);
                    schedule(&mut redraw_at);
                }
                Ok(None) => {}
                Err(message) => {
                    model.mode = Mode::Browse;
                    model.message = Some(message);
                    model.message_since = Some(Instant::now());
                    schedule(&mut redraw_at);
                }
            }
            continue;
        }
        let prior = model.message.clone();
        let action = reduce(model, event, writer);
        schedule(&mut redraw_at);
        if model.message != prior {
            model.message_since = model.message.as_ref().map(|_| Instant::now());
        }
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
            if matches!(model.mode, Mode::Browse) {
                model.mark_saved(&path);
            } else {
                set_row(model, &path, true);
                model.message = Some(format!("saved {path}"));
            }
        }
        Completion::SaveFailed {
            path,
            value,
            message,
        } => {
            model.mode = Mode::ProviderFailure {
                message,
                path,
                value,
            };
        }
        Completion::Deleted(path) => {
            if matches!(model.mode, Mode::Browse) {
                model.mark_deleted(&path);
            } else {
                set_row(model, &path, false);
                model.message = Some(format!("deleted {path}"));
            }
        }
        Completion::Revealed { path, value } => {
            if matches!(model.mode, Mode::Browse)
                && model.selected().and_then(|row| row.path.as_deref()) == Some(path.as_str())
            {
                model.mode = Mode::Reveal {
                    path,
                    value,
                    scroll: 0,
                };
            }
        }
        Completion::Copied(message) | Completion::Failed(message) => model.message = Some(message),
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
        Completion::ApprovalDone(Some(request)) => model.mode = Mode::Approval(request),
        Completion::ApprovalDone(None) => {
            model.mode = Mode::Browse;
            model.message = Some("deployment request finished".into());
        }
        Completion::ApprovalLost(message) => {
            model.mode = Mode::Browse;
            model.message = Some(message);
        }
    }
    model.message_since = model.message.as_ref().map(|_| Instant::now());
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
