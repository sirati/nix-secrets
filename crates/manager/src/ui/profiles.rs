use super::*;

pub(super) fn reduce(
    model: &mut Model,
    mode: Mode,
    event: UiEvent,
    writer: &mut impl SecretWriter,
) {
    match mode {
        Mode::Profiles { mut selected } => {
            let names = model.profiles.profiles.keys().cloned().collect::<Vec<_>>();
            selected = match event {
                UiEvent::Up => selected.saturating_sub(1),
                UiEvent::Down => (selected + 1).min(names.len()),
                _ => selected,
            };
            model.mode = match event {
                UiEvent::Escape => Mode::Browse,
                UiEvent::Character('n') => Mode::ProfileSave {
                    name: String::new(),
                },
                UiEvent::Enter if selected == 0 => Mode::ProfileSave {
                    name: String::new(),
                },
                UiEvent::Enter => {
                    if let Some(name) = names.get(selected - 1) {
                        match model.load_profile(name) {
                            Ok(()) => model.notify(format!("loaded view profile {name}")),
                            Err(error) => model.notify(error),
                        }
                    }
                    Mode::Browse
                }
                UiEvent::Character('s') if selected > 0 => Mode::ProfileOverwrite {
                    name: names[selected - 1].clone(),
                },
                UiEvent::Character('d') if selected > 0 => Mode::ProfileDelete {
                    name: names[selected - 1].clone(),
                },
                _ => Mode::Profiles { selected },
            };
        }
        Mode::ProfileSave { mut name } => match event {
            UiEvent::Escape => model.mode = Mode::Profiles { selected: 0 },
            UiEvent::Backspace => {
                name.pop();
                model.mode = Mode::ProfileSave { name };
            }
            UiEvent::Character(character) if name.len() < 64 => {
                name.push(character);
                model.mode = Mode::ProfileSave { name };
            }
            UiEvent::Paste(bytes) => {
                if let Ok(value) = String::from_utf8(bytes) {
                    name.push_str(&value);
                }
                model.mode = Mode::ProfileSave { name };
            }
            UiEvent::Enter if name.is_empty() => {
                model.notify("enter a profile name");
                model.mode = Mode::ProfileSave { name };
            }
            UiEvent::Enter if model.profiles.profiles.contains_key(&name) => {
                model.mode = Mode::ProfileOverwrite { name };
            }
            UiEvent::Enter => save(model, writer, name),
            _ => model.mode = Mode::ProfileSave { name },
        },
        Mode::ProfileOverwrite { name } => match event {
            UiEvent::Character('y') => save(model, writer, name),
            UiEvent::Character('n') | UiEvent::Escape => {
                model.mode = Mode::Profiles { selected: 0 }
            }
            _ => model.mode = Mode::ProfileOverwrite { name },
        },
        Mode::ProfileDelete { name } => match event {
            UiEvent::Character('y') => {
                match writer.delete_profile(name.clone(), model.profiles.revision) {
                    Ok(snapshot) => {
                        model.profiles = snapshot;
                        model.notify(format!("deleted view profile {name}"));
                    }
                    Err(error) if error == OPERATION_QUEUED => {}
                    Err(error) => model.notify(error),
                }
                model.mode = Mode::Browse;
            }
            UiEvent::Character('n') | UiEvent::Escape => {
                model.mode = Mode::Profiles { selected: 0 }
            }
            _ => model.mode = Mode::ProfileDelete { name },
        },
        _ => unreachable!(),
    }
}

fn save(model: &mut Model, writer: &mut impl SecretWriter, name: String) {
    match writer.save_profile(
        name.clone(),
        model.capture_profile(),
        model.profiles.revision,
    ) {
        Ok(snapshot) => {
            model.profiles = snapshot;
            model.active_profile = Some(name.clone());
            model.notify(format!("saved view profile {name}"));
        }
        Err(error) if error == OPERATION_QUEUED => {}
        Err(error) => model.notify(error),
    }
    model.mode = Mode::Browse;
}
