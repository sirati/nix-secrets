use super::*;

pub fn reduce(model: &mut Model, event: UiEvent, writer: &mut impl SecretWriter) -> Action {
    if let Some(action) = prelude::handle(model, &event, writer) {
        return action;
    }
    let mode = std::mem::replace(&mut model.mode, Mode::Browse);
    match (mode, event) {
        (Mode::Browse, UiEvent::Up) => model.move_by(-1),
        (Mode::Browse, UiEvent::Down) => model.move_by(1),
        (Mode::Browse, UiEvent::Character('f')) => model.cycle_filter(),
        (Mode::Browse, UiEvent::Character('F')) => {
            model.set_filter(crate::model::ViewFilter::All);
            model.set_human_only(false);
            model.mode = Mode::FacetCategories { selected: 0 }
        }
        (Mode::Browse, UiEvent::Character('T')) => model.mode = Mode::TreeOrder { selected: 0 },
        (
            mode @ (Mode::FacetCategories { .. }
            | Mode::FacetValues { .. }
            | Mode::FacetFirstChoice { .. }
            | Mode::TreeOrder { .. }),
            event,
        ) => facets::reduce(model, mode, event),
        (Mode::Browse, UiEvent::Character('h')) => model.toggle_human(),
        (Mode::Browse, UiEvent::Character('1')) => {
            model.set_filter(crate::model::ViewFilter::Required)
        }
        (Mode::Browse, UiEvent::Character('2')) => model.set_filter(crate::model::ViewFilter::All),
        (Mode::Browse, UiEvent::Character('3')) => model.set_filter(crate::model::ViewFilter::Keys),
        (Mode::Browse, UiEvent::Character('4')) => {
            model.set_filter(crate::model::ViewFilter::Passwords)
        }
        (Mode::Browse, UiEvent::Character('5')) => {
            model.set_filter(crate::model::ViewFilter::PublicInfo)
        }
        (Mode::Browse, UiEvent::Character('6')) => model.set_human_only(false),
        (Mode::Browse, UiEvent::Character('7')) => model.set_human_only(true),
        (Mode::Browse, UiEvent::Character('G')) => {
            let paths = model
                .rows
                .iter()
                .filter(|row| {
                    row.category == crate::tree::RowCategory::Password
                        && row.is_secret()
                        && !row.is_set
                        && row.can_generate
                })
                .filter_map(|row| row.path.clone())
                .collect::<Vec<_>>();
            model.mode = Mode::BulkGenerateConfirm { paths };
        }
        (Mode::BulkGenerateConfirm { paths }, UiEvent::Character(choice @ ('p' | 'w'))) => {
            let kind = if choice == 'p' {
                GenerateKind::Password
            } else {
                GenerateKind::Passphrase
            };
            if paths.is_empty() {
                model.notify("No missing passwords to generate");
            } else {
                let total = paths.len();
                match writer.generate_missing(paths, kind) {
                    Ok(()) => model.mode = Mode::BulkProgress { total, done: 0 },
                    Err(error) => model.notify(error),
                }
            }
        }
        (Mode::BulkGenerateConfirm { .. }, UiEvent::Escape) => {}
        (Mode::BulkGenerateConfirm { paths }, _) => {
            model.mode = Mode::BulkGenerateConfirm { paths }
        }
        (Mode::BulkProgress { .. }, UiEvent::Escape) => {}
        (Mode::BulkProgress { total, done }, _) => model.mode = Mode::BulkProgress { total, done },
        (Mode::Browse, UiEvent::Character('?')) => model.mode = Mode::Help { scroll: 0 },
        (Mode::Browse, UiEvent::Character('P'))
            if model.selected().is_some_and(|row| row.is_secret()) =>
        {
            model.mode = Mode::Properties { scroll: 0 }
        }
        (Mode::Properties { scroll }, UiEvent::Up) => {
            model.mode = Mode::Properties {
                scroll: scroll.saturating_sub(1),
            }
        }
        (Mode::Properties { scroll }, UiEvent::Down) => {
            model.mode = Mode::Properties {
                scroll: scroll.saturating_add(1),
            }
        }
        (Mode::Properties { .. }, UiEvent::Escape | UiEvent::Enter) => {}
        (Mode::Properties { scroll }, _) => model.mode = Mode::Properties { scroll },
        (Mode::Help { scroll }, UiEvent::Up) => {
            model.mode = Mode::Help {
                scroll: scroll.saturating_sub(1),
            }
        }
        (Mode::Help { scroll }, UiEvent::Down) => {
            model.mode = Mode::Help {
                scroll: scroll.saturating_add(1),
            }
        }
        (Mode::Help { .. }, UiEvent::Escape | UiEvent::Character('?')) => {}
        (Mode::Help { scroll }, _) => model.mode = Mode::Help { scroll },
        (Mode::Browse, UiEvent::Character('/')) => {
            model.mode = Mode::Search {
                query: model.search.clone(),
            }
        }
        (Mode::Search { mut query }, UiEvent::Character(character)) => {
            query.push(character);
            model.search = query.clone();
            model.selected = 0;
            model.mode = Mode::Search { query };
        }
        (Mode::Search { mut query }, UiEvent::Backspace) => {
            query.pop();
            model.search = query.clone();
            model.selected = 0;
            model.mode = Mode::Search { query };
        }
        (Mode::Search { .. }, UiEvent::Enter) => {}
        (Mode::Search { .. }, UiEvent::Escape) => {
            model.search.clear();
            model.selected = 0;
        }
        (Mode::Search { query }, _) => model.mode = Mode::Search { query },
        (Mode::Browse, UiEvent::Enter) => model.begin_value(Vec::new()),
        (Mode::Browse, UiEvent::Paste(value)) => {
            model.begin_value(value);
            submit_if_edit(model, writer);
        }
        (Mode::Browse, UiEvent::Character('g')) => generated::begin(model, writer),
        (choice @ Mode::GenerateChoice { .. }, event) => {
            return generated::choose(model, writer, choice, event)
        }
        (Mode::Browse, UiEvent::Character('d')) => match model.selected().cloned() {
            Some(row) if row.is_secret() && row.is_set => {
                model.mode = Mode::DeleteConfirm {
                    path: row.path.expect("secret row has path"),
                }
            }
            _ => model.notify("select a set secret to delete"),
        },
        (Mode::Browse, UiEvent::Character('r')) => match model.selected().cloned() {
            Some(row) if row.is_secret() && row.is_set => {
                let path = row.path.expect("secret row has path");
                match writer.reveal(&path) {
                    Ok(value) => {
                        model.mode = Mode::Reveal {
                            path,
                            value,
                            scroll: 0,
                        }
                    }
                    Err(error) => notify_operation_result(model, error),
                }
            }
            _ => model.notify("select a set secret to reveal"),
        },
        (Mode::Browse, UiEvent::Character('c')) => match model.selected().cloned() {
            Some(row) if row.is_secret() && row.is_set => {
                let path = row.path.expect("secret row has path");
                let result = match writer.reveal(&path).and_then(|value| writer.copy(&value)) {
                    Ok(()) => format!("copied {path}"),
                    Err(error) => error,
                };
                notify_operation_result(model, result);
            }
            _ => model.notify("select a set secret to copy"),
        },
        (Mode::Browse, UiEvent::Character('p')) => match model.selected().cloned() {
            Some(row) if row.is_secret() && row.is_set => {
                let path = row.path.expect("secret row has path");
                notify_operation_result(
                    model,
                    match writer.copy_public(&path) {
                        Ok(()) => format!("copied public key for {path}"),
                        Err(error) => error,
                    },
                );
            }
            _ => model.notify("select a set OpenSSH private key"),
        },
        (Mode::DeleteConfirm { path }, UiEvent::Character('y')) => match writer.delete(&path) {
            Ok(()) => model.mark_deleted(&path),
            Err(error) => notify_operation_result(model, error),
        },
        (Mode::DeleteConfirm { .. }, UiEvent::Character('n') | UiEvent::Escape) => {}
        (Mode::DeleteConfirm { path }, _) => model.mode = Mode::DeleteConfirm { path },
        (Mode::Reveal { .. }, UiEvent::Escape | UiEvent::Enter) => {}
        (
            Mode::Reveal {
                path,
                value,
                scroll,
            },
            UiEvent::Up,
        ) => {
            model.mode = Mode::Reveal {
                path,
                value,
                scroll: scroll.saturating_sub(1),
            }
        }
        (
            Mode::Reveal {
                path,
                value,
                scroll,
            },
            UiEvent::Down,
        ) => {
            model.mode = Mode::Reveal {
                path,
                value,
                scroll: scroll.saturating_add(1),
            }
        }
        (
            Mode::Reveal {
                path,
                value,
                scroll,
            },
            UiEvent::Character('c'),
        ) => {
            notify_operation_result(
                model,
                match writer.copy(&value) {
                    Ok(()) => "value copied".into(),
                    Err(error) => error,
                },
            );
            model.mode = Mode::Reveal {
                path,
                value,
                scroll,
            };
        }
        (
            Mode::Reveal {
                path,
                value,
                scroll,
            },
            _,
        ) => {
            model.mode = Mode::Reveal {
                path,
                value,
                scroll,
            }
        }
        (Mode::Browse, UiEvent::Escape) => return Action::Quit,
        (Mode::Edit { path, mut value }, UiEvent::Character(character)) => {
            let mut bytes = [0; 4];
            value.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
            model.mode = Mode::Edit { path, value };
        }
        (Mode::Edit { path, mut value }, UiEvent::Backspace) => {
            truncate_character(&mut value);
            model.mode = Mode::Edit { path, value };
        }
        (Mode::Edit { path, value }, UiEvent::Enter) => submit(model, writer, path, value),
        (Mode::Edit { .. }, UiEvent::Escape) => {}
        (Mode::Edit { path, value }, _) => model.mode = Mode::Edit { path, value },
        (Mode::Replace { path, value }, UiEvent::Character('y')) => {
            model.mode = Mode::Edit { path, value };
            submit_if_nonempty(model, writer);
        }
        (Mode::Replace { .. }, UiEvent::Character('n') | UiEvent::Escape) => {}
        (Mode::Replace { path, value }, _) => model.mode = Mode::Replace { path, value },
        (preview @ Mode::GeneratedPreview { .. }, event) => {
            return generated::reduce(model, writer, preview, event)
        }
        (failure @ Mode::ProviderFailure { .. }, event) => {
            provider_failure::reduce(model, writer, failure, event);
        }
        (Mode::Approval(request), event) => {
            let action = approval::reduce(model, writer, request, event);
            if action != Action::Continue {
                return action;
            }
        }
        (Mode::Browse, _) => {}
    }
    model.show_pending_approval();
    Action::Continue
}
