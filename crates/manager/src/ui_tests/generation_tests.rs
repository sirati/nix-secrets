use super::*;

#[test]
fn generated_value_is_masked_and_copy_is_explicit() {
    let mut model = model(false);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('g'), &mut writer);
    assert!(matches!(model.mode, Mode::GenerateChoice { .. }));
    reduce(&mut model, UiEvent::Character('p'), &mut writer);
    assert!(matches!(
        model.mode,
        Mode::GeneratedPreview {
            revealed: false,
            ..
        }
    ));
    assert!(writer.copies.is_empty());
    reduce(&mut model, UiEvent::Character('c'), &mut writer);
    assert_eq!(writer.copies, [b"generated-value"]);
    assert!(matches!(
        model.mode,
        Mode::GeneratedPreview {
            revealed: false,
            ..
        }
    ));
    reduce(&mut model, UiEvent::Character('r'), &mut writer);
    assert!(matches!(
        model.mode,
        Mode::GeneratedPreview { revealed: true, .. }
    ));
}

#[test]
fn generated_replacement_requires_confirmation() {
    let mut model = model(true);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('g'), &mut writer);
    reduce(&mut model, UiEvent::Character('w'), &mut writer);
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert!(matches!(model.mode, Mode::Replace { .. }));
    assert!(writer.writes.is_empty());
    reduce(&mut model, UiEvent::Character('y'), &mut writer);
    assert_eq!(writer.writes, [b"generated-value"]);
}

#[test]
fn generated_unset_value_is_encrypted_immediately_after_acceptance() {
    let mut model = model(false);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('g'), &mut writer);
    reduce(&mut model, UiEvent::Character('p'), &mut writer);
    reduce(&mut model, UiEvent::Enter, &mut writer);
    assert_eq!(writer.writes, [b"generated-value"]);
    assert!(model.rows[0].is_set);
}

#[test]
fn non_password_leaf_does_not_open_a_preview() {
    let mut model = model(false);
    let mut writer = writer();
    model.rows[0].can_generate = false;
    reduce(&mut model, UiEvent::Character('g'), &mut writer);
    assert!(matches!(model.mode, Mode::Browse));
    assert_eq!(model.message.as_deref(), Some("select a password leaf"));
}

#[test]
fn generated_plaintext_is_redacted_from_debug_output() {
    let mode = Mode::GeneratedPreview {
        path: "h.services.s.key".into(),
        value: Zeroizing::new(b"must-never-be-logged".to_vec()),
        revealed: true,
        replacing: false,
    };
    let debug = format!("{mode:?}");
    assert!(!debug.contains("must-never-be-logged"));
    assert!(debug.contains("<redacted>"));
}
