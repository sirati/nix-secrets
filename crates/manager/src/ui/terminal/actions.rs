use super::*;
use crate::model::NoticeSeverity;
use buttons::Button;

fn key(label: &'static str, shortcut: Shortcut) -> Button {
    Button::new(label, MouseTarget::Shortcut(shortcut))
}
fn letter(label: &'static str, character: char) -> Button {
    key(label, Shortcut::Character(character))
}

pub(super) fn hotkeys(model: &Model, narrow: bool) -> Vec<Button> {
    // An informational notice leaves the current actions usable; a failure
    // offers only its OK button.
    if model
        .message
        .as_ref()
        .is_some_and(|notice| notice.severity == NoticeSeverity::Failure)
    {
        return vec![key("Enter OK", Shortcut::Enter)];
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
                    letter("P Properties", 'P').enabled(editable),
                    letter("F Filter", 'F'),
                    letter("T Tree", 'T'),
                    letter("S Profiles", 'S'),
                    letter("O Settings", 'O'),
                    letter("/ Search", '/'),
                    key("Enter Edit", Shortcut::Enter).enabled(editable),
                    letter("G Missing", 'G').enabled(missing),
                ]
            } else {
                vec![
                    letter("? Help", '?'),
                    letter("P Properties", 'P').enabled(editable),
                    letter("F Filter", 'F'),
                    letter("T Tree", 'T'),
                    letter("S Profiles", 'S'),
                    letter("O Settings", 'O'),
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
        Mode::FacetCategories { .. } => vec![
            key("Enter Open", Shortcut::Enter),
            key("Esc Close", Shortcut::Escape),
        ],
        Mode::FacetValues { .. } => vec![
            key("Enter Select", Shortcut::Enter),
            key("Esc Categories", Shortcut::Escape),
        ],
        Mode::FacetFirstChoice { .. } => vec![
            letter("1 Only this", '1'),
            letter("2 Only others", '2'),
            letter("3 Whitelist off", '3'),
            letter("4 Blacklist off", '4'),
            key("Esc Back", Shortcut::Escape),
        ],
        Mode::TreeOrder { .. } => vec![
            letter("Space Toggle", ' '),
            letter("[ Earlier", '['),
            letter("] Later", ']'),
            key("Esc Done", Shortcut::Escape),
        ],
        Mode::Profiles { .. } => vec![
            key("Enter Load/New", Shortcut::Enter),
            letter("n New", 'n'),
            letter("s Save over", 's'),
            letter("d Delete", 'd'),
            key("Esc Close", Shortcut::Escape),
        ],
        Mode::ProfileSave { .. } => vec![
            key("Enter Save", Shortcut::Enter),
            key("Esc Cancel", Shortcut::Escape),
        ],
        Mode::ProfileOverwrite { .. } => vec![letter("y Replace", 'y'), letter("n Cancel", 'n')],
        Mode::ProfileDelete { .. } => vec![letter("y Delete", 'y'), letter("n Cancel", 'n')],
        Mode::Help { .. } => vec![key("Esc Close", Shortcut::Escape)],
        Mode::Settings { .. } => vec![
            key("Enter Toggle", Shortcut::Enter),
            key("Esc Close", Shortcut::Escape),
        ],
        Mode::Properties { .. } => vec![key("Esc Close", Shortcut::Escape)],
        Mode::Search { .. } => vec![
            key("Enter Keep", Shortcut::Enter),
            key("Esc Clear", Shortcut::Escape),
        ],
        Mode::DeleteConfirm { .. } => vec![letter("y Delete", 'y'), letter("n Cancel", 'n')],
        Mode::Replace {
            commit: nix_secrets_core::CommitState::Committed,
            ..
        } => vec![letter("y Replace", 'y'), letter("n Cancel", 'n')],
        Mode::Replace { .. } => vec![
            Button::new("Ctrl+Shift+Y Yes, overwrite", MouseTarget::ConfirmLoss),
            key("Enter No", Shortcut::Enter),
        ],
        Mode::Reveal { .. } => vec![key("Esc Hide", Shortcut::Escape), letter("c Copy", 'c')],
        Mode::Edit { .. } => vec![
            key("Enter Save", Shortcut::Enter),
            key("Esc Cancel", Shortcut::Escape),
            Button::new(
                if model.settings.autosave_unset_on_paste {
                    "Tab ☑ Autosave on paste"
                } else {
                    "Tab □ Autosave on paste"
                },
                MouseTarget::AutosaveToggle,
            ),
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
