use super::*;

#[test]
fn all_to_value_filter_offers_four_distinct_rules() {
    use crate::model::{Attribute, FacetMode, ViewFilter};
    for (choice, mode, expected) in [
        ('1', FacetMode::Whitelist, vec!["key"]),
        ('2', FacetMode::Blacklist, vec!["key"]),
        ('3', FacetMode::Whitelist, vec!["other"]),
        ('4', FacetMode::Blacklist, vec!["other"]),
    ] {
        let mut model = model(false);
        let mut other = model.rows[0].clone();
        other.name = "other".into();
        other.path = Some("h.services.s.other".into());
        model.rows.push(other);
        model.set_filter(ViewFilter::All);
        let mut writer = writer();
        reduce(&mut model, UiEvent::Character('F'), &mut writer);
        assert!(matches!(model.mode, Mode::FacetCategories { .. }));
        reduce(
            &mut model,
            UiEvent::Click(MouseTarget::ModalItem(6)),
            &mut writer,
        );
        assert!(matches!(
            model.mode,
            Mode::FacetValues {
                attribute: Attribute::Name,
                ..
            }
        ));
        reduce(
            &mut model,
            UiEvent::Click(MouseTarget::ModalItem(3)),
            &mut writer,
        );
        assert!(matches!(model.mode, Mode::FacetFirstChoice { .. }));
        reduce(&mut model, UiEvent::Character(choice), &mut writer);
        let facet = model.facet(Attribute::Name);
        assert_eq!(facet.mode, mode);
        assert_eq!(facet.selected.into_iter().collect::<Vec<_>>(), expected);
    }
}

#[test]
fn tree_editor_moves_attributes_between_tree_and_filter_only() {
    use crate::model::Attribute;
    let mut model = model(false);
    let mut writer = writer();
    reduce(&mut model, UiEvent::Character('T'), &mut writer);
    assert!(matches!(model.mode, Mode::TreeOrder { .. }));
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::ModalItem(2)),
        &mut writer,
    );
    assert!(matches!(model.mode, Mode::TreeOrder { selected: 2 }));
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    assert!(!model.tree_order.contains(&Attribute::Service));
    reduce(
        &mut model,
        UiEvent::Click(MouseTarget::ModalItem(10)),
        &mut writer,
    );
    reduce(&mut model, UiEvent::Character(' '), &mut writer);
    assert!(model.tree_order.contains(&Attribute::Status));
    reduce(&mut model, UiEvent::Character('['), &mut writer);
    assert_ne!(model.tree_order.last(), Some(&Attribute::Status));
    reduce(&mut model, UiEvent::Escape, &mut writer);
    assert!(matches!(model.mode, Mode::Browse));
}
