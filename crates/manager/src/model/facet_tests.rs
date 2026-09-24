use super::*;
use nix_secrets_core::schema::{SecretIdentity, SecretPresentation};

fn leaf(namespace: &str, name: &str) -> Row {
    Row {
        depth: 0,
        name: name.into(),
        display_segments: vec![],
        path: Some(format!("host.services.legacy-{namespace}.{name}")),
        is_set: false,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: Some(format!("{namespace} mail credential")),
        category: RowCategory::Password,
        human_facing: false,
        external_input_required: false,
        identity: Some(SecretIdentity {
            host: "host".into(),
            scope: "system".into(),
            user: None,
            service: "mail".into(),
            responsibility: "backup".into(),
            namespace: Some(namespace.into()),
            name: name.into(),
        }),
        presentation: Some(SecretPresentation {
            explanation: format!("{namespace} mail credential"),
            facing: "generated".into(),
            value_type: "passphrase".into(),
        }),
    }
}

fn identifiers(model: &Model) -> Vec<String> {
    model
        .visible_rows()
        .iter()
        .filter_map(|index| model.rows[*index].path.clone())
        .collect()
}

#[test]
fn tree_order_and_subset_change_presentation_without_changing_storage_ids() {
    let mut model = Model::new(vec![leaf("alpha", "token"), leaf("beta", "token")]);
    model.set_filter(ViewFilter::All);
    assert!(model.rows.iter().any(|row| row.name == "mail"));
    let ids = identifiers(&model);
    model.tree_order = vec![Attribute::Namespace, Attribute::Type];
    model.rebuild_tree();
    assert_eq!(identifiers(&model), ids);
    assert!(model
        .rows
        .iter()
        .any(|row| row.depth == 0 && row.name == "alpha"));
    assert!(model
        .rows
        .iter()
        .any(|row| row.depth == 1 && row.name == "passphrase"));
    model.tree_order.clear();
    model.rebuild_tree();
    assert_eq!(identifiers(&model), ids);
    assert!(model
        .rows
        .iter()
        .filter(|row| row.is_secret())
        .all(|row| row.name == "token"));
    let labels = model
        .visible_tree_rows()
        .into_iter()
        .filter(|row| model.rows[row.index].is_secret())
        .map(|row| row.label)
        .collect::<Vec<_>>();
    assert_eq!(labels, ["token", "token"]);
    model.selected = 0;
    let first = model.selected_display_path().unwrap();
    model.selected = 1;
    let second = model.selected_display_path().unwrap();
    assert_ne!(first, second);
    assert!(first.contains("alpha") || second.contains("alpha"));
    assert!(first.contains("beta") || second.contains("beta"));
    assert!(first.contains("mail") && second.contains("mail"));
}

#[test]
fn whitelist_blacklist_inversion_preserves_visible_values() {
    let mut model = Model::new(vec![leaf("alpha", "a"), leaf("beta", "b")]);
    model.set_filter(ViewFilter::All);
    let mut facet = Facet {
        mode: FacetMode::Whitelist,
        selected: ["alpha".to_owned()].into(),
    };
    model.set_facet(Attribute::Namespace, facet.clone());
    let before = identifiers(&model);
    assert_eq!(before.len(), 1);
    facet.set_mode(
        FacetMode::Blacklist,
        &model.facet_values(Attribute::Namespace),
    );
    assert_eq!(facet.selected, ["beta".to_owned()].into());
    model.set_facet(Attribute::Namespace, facet);
    assert_eq!(identifiers(&model), before);
}
