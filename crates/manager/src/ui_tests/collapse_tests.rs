//! Collapsing tree groups with Space and clicks.
use super::*;
use nix_secrets_core::schema::SecretIdentity;

/// A value under `host > system > service > backup`, cloned from the shared
/// fixture so new row fields need no change here.
fn leaf(service: &str, name: &str, set: bool) -> Row {
    let mut row = model(set).rows[0].clone();
    row.name = name.into();
    row.path = Some(format!("h.services.{service}.{name}"));
    row.identity = Some(SecretIdentity {
        host: "h".into(),
        scope: "system".into(),
        user: None,
        service: service.into(),
        responsibility: "backup".into(),
        namespace: None,
        name: name.into(),
    });
    row
}

fn tree() -> Model {
    Model::new(vec![
        leaf("mail", "password", false),
        leaf("mail", "token", true),
        leaf("web", "key", false),
    ])
}

fn labels(model: &Model) -> Vec<String> {
    model
        .visible_tree_rows()
        .into_iter()
        .map(|row| row.label)
        .collect()
}

fn select(model: &mut Model, label: &str) {
    model.selected = labels(model)
        .iter()
        .position(|candidate| candidate == label)
        .unwrap_or_else(|| panic!("{label} not in {:?}", labels(model)));
}

fn selected_label(model: &Model) -> String {
    labels(model)[model.selected].clone()
}

#[test]
fn fixture_tree_has_groups_and_values() {
    assert_eq!(
        labels(&tree()),
        [
            "h",
            "system",
            "mail/backup",
            "password",
            "token",
            "web/backup/key"
        ]
    );
}

#[test]
fn space_toggles_the_selected_group() {
    let mut model = tree();
    let mut writer = writer();
    select(&mut model, "mail/backup");
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    assert_eq!(
        labels(&model),
        ["h", "system", "mail/backup", "web/backup/key"]
    );
    assert_eq!(selected_label(&model), "mail/backup");
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    assert_eq!(labels(&tree()), labels(&model));
    assert!(matches!(model.mode, Mode::Browse));
}

#[test]
fn space_on_a_value_changes_nothing() {
    let mut model = tree();
    let mut writer = writer();
    select(&mut model, "password");
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    assert_eq!(labels(&model), labels(&tree()));
    assert!(matches!(model.mode, Mode::Browse));
    assert!(writer.writes.is_empty());
}

#[test]
fn space_keeps_its_meaning_in_the_entry_field() {
    let mut model = tree();
    let mut writer = writer();
    select(&mut model, "password");
    reduce(&mut model, UiEvent::Enter, &mut writer);
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    let Mode::Edit { value, .. } = &model.mode else {
        panic!("entry field closed")
    };
    assert_eq!(value.as_slice(), b" ");
    assert!(model.collapsed.is_empty());
}

#[test]
fn a_click_on_a_group_selects_and_toggles_it() {
    let mut model = tree();
    let mut writer = writer();
    let mail = labels(&model)
        .iter()
        .position(|label| label == "mail/backup")
        .unwrap();
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Tree(mail)),
        &mut writer,
    );
    assert_eq!(selected_label(&model), "mail/backup");
    assert_eq!(
        labels(&model),
        ["h", "system", "mail/backup", "web/backup/key"]
    );
    assert!(matches!(model.mode, Mode::Browse));
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Tree(mail)),
        &mut writer,
    );
    assert_eq!(labels(&model), labels(&tree()));
}

#[test]
fn a_click_on_an_unset_value_still_opens_entry() {
    let mut model = tree();
    let mut writer = writer();
    let password = labels(&model)
        .iter()
        .position(|label| label == "password")
        .unwrap();
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Tree(password)),
        &mut writer,
    );
    assert!(matches!(&model.mode, Mode::Edit { path, .. } if path == "h.services.mail.password"));
    assert!(model.collapsed.is_empty());
}

#[test]
fn a_click_on_a_set_value_only_selects_it() {
    let mut model = tree();
    let mut writer = writer();
    let token = labels(&model)
        .iter()
        .position(|label| label == "token")
        .unwrap();
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Tree(token)),
        &mut writer,
    );
    assert!(matches!(model.mode, Mode::Browse));
    assert_eq!(selected_label(&model), "token");
    assert_eq!(labels(&model), labels(&tree()));
}

#[test]
fn collapsing_an_ancestor_moves_the_selection_to_it() {
    let mut model = tree();
    let mut writer = writer();
    select(&mut model, "system");
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    select(&mut model, "system");
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    // `-` collapses everything while the cursor is on a deep value.
    select(&mut model, "token");
    reduce(&mut model, UiEvent::Character('-'), &mut writer);
    assert_eq!(labels(&model), ["h"]);
    assert_eq!(selected_label(&model), "h");
    reduce(&mut model, UiEvent::Character('+'), &mut writer);
    assert_eq!(labels(&model), labels(&tree()));
    assert_eq!(selected_label(&model), "h");
}

#[test]
fn a_refresh_keeps_collapsed_groups_and_the_selection() {
    let mut model = tree();
    let mut writer = writer();
    select(&mut model, "mail/backup");
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    select(&mut model, "web/backup/key");
    // The backend reports a value change and a new value in another group.
    model.update_rows(vec![
        leaf("mail", "password", true),
        leaf("mail", "token", true),
        leaf("web", "key", false),
        leaf("web", "cert", false),
    ]);
    assert_eq!(
        labels(&model),
        ["h", "system", "mail/backup", "web/backup", "cert", "key"]
    );
    assert_eq!(selected_label(&model), "key");
    // A selected collapsed group stays selected across a refresh too.
    select(&mut model, "mail/backup");
    model.update_rows(vec![
        leaf("mail", "password", true),
        leaf("mail", "token", false),
        leaf("web", "key", false),
    ]);
    assert_eq!(selected_label(&model), "mail/backup");
}

#[test]
fn a_filter_change_keeps_collapsed_groups() {
    let mut model = tree();
    let mut writer = writer();
    select(&mut model, "mail/backup");
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    reduce(&mut model, UiEvent::Character('2'), &mut writer);
    reduce(&mut model, UiEvent::Character('1'), &mut writer);
    assert_eq!(
        labels(&model),
        ["h", "system", "mail/backup", "web/backup/key"]
    );
}

#[test]
fn a_search_shows_matches_inside_collapsed_groups() {
    let mut model = tree();
    let mut writer = writer();
    select(&mut model, "mail/backup");
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    reduce(&mut model, UiEvent::Character('/'), &mut writer);
    for character in "tok".chars() {
        reduce(&mut model, UiEvent::Character(character), &mut writer);
    }
    reduce(&mut model, UiEvent::Enter, &mut writer);
    // The collapsed group holding the match is expanded while searching.
    assert!(
        labels(&model).iter().any(|label| label.ends_with("token")),
        "{:?}",
        labels(&model)
    );
    // Groups can be folded within the results.
    select(&mut model, "h");
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    assert_eq!(labels(&model), ["h"]);
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    // Leaving the search restores the folds from before it.
    reduce(&mut model, UiEvent::Character('/'), &mut writer);
    reduce(&mut model, UiEvent::Escape, &mut writer);
    assert_eq!(
        labels(&model),
        ["h", "system", "mail/backup", "web/backup/key"]
    );
}
