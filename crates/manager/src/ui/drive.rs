use super::*;
use std::time::{Duration, Instant};

pub fn drive(
    frontend: &mut impl Frontend,
    writer: &mut impl SecretWriter,
    model: &mut Model,
) -> io::Result<()> {
    loop {
        frontend.draw(model)?;
        let event = frontend.read()?;
        if event == UiEvent::Tick {
            if matches!(model.mode, Mode::Browse) {
                match writer.refresh_rows() {
                    Ok(Some(rows)) => model.update_rows(rows),
                    Ok(None) => {}
                    Err(error) => {
                        model.message = Some(error);
                        model.message_since = Some(Instant::now());
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
            }
            match writer.poll_approval() {
                Ok(Some(request)) => {
                    model.apply_task_status(&request);
                    model.mode = Mode::Approval(request);
                }
                Ok(None) => {}
                Err(message) => {
                    model.mode = Mode::Browse;
                    model.message = Some(message);
                    model.message_since = Some(Instant::now());
                }
            }
            continue;
        }
        let prior = model.message.clone();
        let action = reduce(model, event, writer);
        if model.message != prior {
            model.message_since = model.message.as_ref().map(|_| Instant::now());
        }
        if action == Action::Quit {
            return Ok(());
        }
    }
}
