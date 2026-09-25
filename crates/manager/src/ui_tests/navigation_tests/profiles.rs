use super::*;
use nix_secrets_core::{ProfileSnapshot, ViewProfile};

#[derive(Default)]
struct ProfileWriter {
    snapshot: ProfileSnapshot,
}

impl SecretWriter for ProfileWriter {
    fn write(
        &mut self,
        _path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        Err(("not used".into(), value))
    }
    fn save_profile(
        &mut self,
        name: String,
        profile: ViewProfile,
        revision: u64,
    ) -> Result<ProfileSnapshot, String> {
        if revision != self.snapshot.revision {
            return Err("stale profile list".into());
        }
        self.snapshot.revision += 1;
        self.snapshot.profiles.insert(name, profile);
        Ok(self.snapshot.clone())
    }
    fn delete_profile(&mut self, name: String, revision: u64) -> Result<ProfileSnapshot, String> {
        if revision != self.snapshot.revision {
            return Err("stale profile list".into());
        }
        self.snapshot.revision += 1;
        self.snapshot.profiles.remove(&name);
        Ok(self.snapshot.clone())
    }
}

#[test]
fn keyboard_and_mouse_profiles_save_load_and_delete_without_losing_unsaved_view() {
    let mut model = model(false);
    let mut writer = ProfileWriter::default();
    model.tree_order = vec![crate::model::Attribute::Host, crate::model::Attribute::Name];
    reduce(&mut model, UiEvent::Character('S'), &mut writer);
    assert!(matches!(model.mode, Mode::Profiles { .. }));
    reduce(&mut model, UiEvent::Character('n'), &mut writer);
    for character in "Laptop".chars() {
        reduce(&mut model, UiEvent::Character(character), &mut writer);
    }
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert!(model.profiles.profiles.contains_key("Laptop"));
    assert_eq!(model.active_profile.as_deref(), Some("Laptop"));
    model.tree_order.clear();
    assert!(model.profile_dirty());
    reduce(&mut model, UiEvent::Character('S'), &mut writer);
    reduce(&mut model, UiEvent::Escape, &mut writer);
    assert!(
        model.tree_order.is_empty(),
        "opening profiles preserves unsaved layout"
    );
    reduce(&mut model, UiEvent::Character('S'), &mut writer);
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::ModalItem(1)),
        &mut writer,
    );
    assert_eq!(
        model.tree_order,
        vec![crate::model::Attribute::Host, crate::model::Attribute::Name]
    );
    assert!(!model.profile_dirty());
    reduce(&mut model, UiEvent::Character('S'), &mut writer);
    reduce(&mut model, UiEvent::Down, &mut writer);
    reduce(&mut model, UiEvent::Character('d'), &mut writer);
    assert!(matches!(model.mode, Mode::ProfileDelete { .. }));
    reduce(&mut model, UiEvent::Character('y'), &mut writer);
    assert!(model.profiles.profiles.is_empty());
}

#[test]
fn success_notice_passes_keys_through_but_never_into_a_confirmation() {
    let mut model = model(false);
    let mut writer = ProfileWriter::default();
    model.rows.push(model.rows[0].clone());
    model.rows[1].path = Some("h.services.s.other".into());
    model.rebuild_tree();
    model.selected = 0;
    model.inform("saved view profile Laptop");
    reduce(&mut model, UiEvent::Down, &mut writer);
    assert!(model.message.is_none());
    assert_eq!(model.selected, 1, "↓ closed the notice and moved");
    model.inform("saved view profile Laptop");
    reduce(&mut model, UiEvent::Character('S'), &mut writer);
    assert!(model.message.is_none());
    assert!(matches!(model.mode, Mode::Profiles { .. }));

    model.mode = Mode::ProfileDelete {
        name: "Laptop".into(),
    };
    model.inform("profiles changed elsewhere");
    reduce(&mut model, UiEvent::Character('y'), &mut writer);
    assert!(model.message.is_none());
    assert!(
        matches!(model.mode, Mode::ProfileDelete { .. }),
        "y only closed the notice above a confirmation"
    );
}

#[test]
fn failure_notice_swallows_keys_until_explicit_ok() {
    let mut model = model(false);
    let mut writer = ProfileWriter::default();
    model.rows.push(model.rows[0].clone());
    model.rebuild_tree();
    model.selected = 0;
    model.fail("age exited with exit code 1");
    reduce(&mut model, UiEvent::Down, &mut writer);
    reduce(&mut model, UiEvent::Character('S'), &mut writer);
    reduce(&mut model, UiEvent::Escape, &mut writer);
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Tree(1)),
        &mut writer,
    );
    assert_eq!(model.message_text(), Some("age exited with exit code 1"));
    assert_eq!(model.selected, 0);
    assert!(matches!(model.mode, Mode::Browse));
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert!(model.message.is_none());
    assert!(matches!(model.mode, Mode::Browse), "Enter only closed it");

    model.fail("second failure");
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Shortcut(Shortcut::Enter)),
        &mut writer,
    );
    assert!(model.message.is_none(), "the OK button closes it");
}

#[test]
fn click_on_success_notice_acts_on_what_is_under_the_pointer() {
    let mut model = model(false);
    let mut writer = ProfileWriter::default();
    model.rows.push(model.rows[0].clone());
    model.rebuild_tree();
    model.inform("saved");
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::Tree(1)),
        &mut writer,
    );
    assert!(model.message.is_none());
    assert_eq!(model.selected, 1);
    model.inform("saved");
    reduce(&mut model, UiEvent::Click(MouseTarget::Notice), &mut writer);
    assert!(model.message.is_none());
    assert_eq!(
        model.selected, 1,
        "clicking the notice itself only closes it"
    );
}

#[test]
fn arrows_under_a_success_notice_move_the_tree_not_the_notice() {
    let mut model = model(false);
    let mut writer = ProfileWriter::default();
    model.rows.push(model.rows[0].clone());
    model.rebuild_tree();
    model.selected = 0;
    model.inform("saved");
    reduce(&mut model, UiEvent::Down, &mut writer);
    assert!(model.message.is_none());
    assert_eq!(model.selected, 1);
    assert_eq!(model.modal_scroll, 0, "the notice never scrolled");
    model.inform("saved");
    reduce(&mut model, UiEvent::Up, &mut writer);
    assert!(model.message.is_none());
    assert_eq!(model.selected, 0);
}
