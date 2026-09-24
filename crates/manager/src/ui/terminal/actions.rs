use super::*;
use buttons::Button;

fn key(label: &'static str, shortcut: Shortcut) -> Button {
    Button::new(label, MouseTarget::Shortcut(shortcut))
}
fn letter(label: &'static str, character: char) -> Button {
    key(label, Shortcut::Character(character))
}

pub(super) fn hotkeys(model: &Model, narrow: bool) -> Vec<Button> {
    if model.message.is_some() {
        return vec![key("Enter Continue", Shortcut::Enter)];
    }
    match &model.mode {
        Mode::Browse => {
            let selected = model.selected();
            let editable = selected.is_some_and(|row| row.is_secret());
            let set = selected.is_some_and(|row| row.is_secret() && row.is_set);
            let generatable = selected.is_some_and(|row| row.can_generate);
            let missing = model
                .rows
                .iter()
                .any(|row| row.can_generate && row.is_secret() && !row.is_set);
            if narrow {
                vec![
                    letter("? Help", '?'),
                    letter("/ Search", '/'),
                    key("Enter Edit", Shortcut::Enter).enabled(editable),
                    letter("G Missing", 'G').enabled(missing),
                ]
            } else {
                vec![
                    letter("? Help", '?'),
                    letter("/ Search", '/'),
                    key("Enter Edit", Shortcut::Enter).enabled(editable),
                    letter("g Generate", 'g').enabled(generatable),
                    letter("G Missing", 'G').enabled(missing),
                    letter("d Delete", 'd').enabled(set),
                    letter("r Reveal", 'r').enabled(set),
                    letter("c Copy", 'c').enabled(set),
                    letter("p Public", 'p')
                        .enabled(selected.is_some_and(|row| row.can_copy_public && row.is_set)),
                ]
            }
        }
        Mode::Help { .. } => vec![key("Esc Close", Shortcut::Escape)],
        Mode::Search { .. } => vec![
            key("Enter Keep", Shortcut::Enter),
            key("Esc Clear", Shortcut::Escape),
        ],
        Mode::DeleteConfirm { .. } => vec![letter("y Delete", 'y'), letter("n Cancel", 'n')],
        Mode::Replace { .. } => vec![letter("y Replace", 'y'), letter("n Cancel", 'n')],
        Mode::Reveal { .. } => vec![key("Esc Hide", Shortcut::Escape), letter("c Copy", 'c')],
        Mode::Edit { .. } => vec![
            key("Enter Save", Shortcut::Enter),
            key("Esc Cancel", Shortcut::Escape),
        ],
        Mode::GenerateChoice { .. } | Mode::BulkGenerateConfirm { .. } => vec![
            letter("p Password", 'p'),
            letter("w Passphrase", 'w'),
            key("Esc Cancel", Shortcut::Escape),
        ],
        Mode::BulkProgress { .. } => vec![key("Esc Hide", Shortcut::Escape)],
        Mode::GeneratedPreview { .. } => vec![
            key("Enter Save", Shortcut::Enter),
            letter("r Reveal", 'r'),
            letter("c Copy", 'c'),
            key("Esc Discard", Shortcut::Escape),
        ],
        Mode::ProviderFailure { .. } => {
            vec![letter("r Retry", 'r'), key("Esc Cancel", Shortcut::Escape)]
        }
        Mode::Approval(_) => vec![letter("y Approve", 'y'), letter("n Reject", 'n')],
    }
}
