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
    reduce(&mut model, UiEvent::Enter, &mut writer); // acknowledge success
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
    reduce(&mut model, UiEvent::Enter, &mut writer); // acknowledge load
    reduce(&mut model, UiEvent::Character('S'), &mut writer);
    reduce(&mut model, UiEvent::Down, &mut writer);
    reduce(&mut model, UiEvent::Character('d'), &mut writer);
    assert!(matches!(model.mode, Mode::ProfileDelete { .. }));
    reduce(&mut model, UiEvent::Character('y'), &mut writer);
    assert!(model.profiles.profiles.is_empty());
}
