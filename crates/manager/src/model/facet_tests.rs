use super::*;
use nix_secrets_core::schema::{SecretIdentity, SecretPresentation};
use std::collections::BTreeSet;

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

#[test]
fn profile_round_trip_restores_order_filters_and_audience_without_search() {
    let mut model = Model::new(vec![leaf("alpha", "token"), leaf("beta", "token")]);
    model.tree_order = vec![Attribute::Namespace, Attribute::Name];
    model.set_filter(ViewFilter::Passwords);
    model.set_human_only(true);
    model.search = "do-not-persist".into();
    model.set_facet(
        Attribute::Namespace,
        Facet {
            mode: FacetMode::Whitelist,
            selected: ["alpha".to_owned()].into(),
        },
    );
    let captured = model.capture_profile();
    let serialized = serde_json::to_string(&captured).unwrap();
    assert!(!serialized.contains("do-not-persist"));
    model
        .profiles
        .profiles
        .insert("work".into(), captured.clone());
    model.tree_order.clear();
    model.facets.clear();
    model.set_filter(ViewFilter::All);
    model.set_human_only(false);
    model.load_profile("work").unwrap();
    assert_eq!(model.capture_profile(), captured);
    assert!(model.search.is_empty());
    assert!(!model.profile_dirty());
    model.tree_order.clear();
    assert!(model.profile_dirty());
}

fn service_leaf(user: Option<&str>, name: &str) -> Row {
    let mut row = leaf("alpha", name);
    let identity = row.identity.as_mut().unwrap();
    identity.scope = if user.is_some() { "user" } else { "system" }.into();
    identity.user = user.map(str::to_owned);
    identity.service = "mail".into();
    row.path = Some(match user {
        Some(user) => format!("host.user-{user}-services.mail.{name}"),
        None => format!("host.services.mail.{name}"),
    });
    row
}

fn mixed_model() -> Model {
    let mut model = Model::new(vec![
        service_leaf(None, "system-key"),
        service_leaf(Some("alice"), "alice-key"),
    ]);
    model.filter = ViewFilter::All;
    model.tree_order = vec![
        Attribute::Host,
        Attribute::Scope,
        Attribute::User,
        Attribute::Service,
        Attribute::Name,
    ];
    model.rebuild_tree();
    model
}

#[test]
fn inapplicable_user_adds_no_tree_level_crumb_facet_value_or_property() {
    let mut model = mixed_model();
    let branches: Vec<(usize, String)> = model
        .rows
        .iter()
        .filter(|row| row.path.is_none())
        .map(|row| (row.depth, row.name.clone()))
        .collect();
    assert_eq!(
        branches,
        [
            (0, "host".to_owned()),
            (1, "system".to_owned()),
            (2, "mail".to_owned()),
            (1, "user".to_owned()),
            (2, "alice".to_owned()),
            (3, "mail".to_owned()),
        ],
        "system services skip the user level; user services keep it"
    );
    assert!(model.rows.iter().all(|row| row.name != "(none)"));
    assert_eq!(
        model.facet_values(Attribute::User),
        BTreeSet::from(["alice".to_owned()])
    );
    model.selected = model
        .visible_rows()
        .iter()
        .position(|index| model.rows[*index].name == "system-key")
        .unwrap();
    let crumb = model.selected_display_path().unwrap();
    assert!(!crumb.contains("(none)"), "{crumb}");
    let row = model.selected().unwrap();
    assert_eq!(Attribute::User.value(row), None);
    assert!(Attribute::ALL
        .iter()
        .filter_map(|attribute| attribute.value(row))
        .all(|value| value != "(none)"));
}

#[test]
fn user_whitelist_filters_only_rows_where_user_applies() {
    let mut model = mixed_model();
    let mut facet = model.facet(Attribute::User);
    facet.mode = FacetMode::Whitelist;
    facet.selected = BTreeSet::from(["bob".to_owned()]);
    model.set_facet(Attribute::User, facet);
    assert_eq!(identifiers(&model), ["host.services.mail.system-key"]);
}

#[test]
fn explanation_is_neither_a_tree_level_nor_a_facet_but_stays_searchable() {
    let mut model = mixed_model();
    assert!(!model
        .tree_editor_attributes()
        .contains(&Attribute::Explanation));
    assert!(!Attribute::GROUPING.contains(&Attribute::Explanation));
    model.search = "alpha mail credential".into();
    assert_eq!(identifiers(&model).len(), 2);
}

#[test]
fn profile_with_explanation_loads_without_it_and_is_not_modified() {
    use nix_secrets_core::{ProfileFacet, ProfileFacetMode, ProfileViewFilter, ViewProfile};
    let mut model = mixed_model();
    model.profiles.profiles.insert(
        "old".into(),
        ViewProfile {
            tree_order: vec!["host".into(), "explanation".into(), "name".into()],
            facets: [(
                "explanation".to_owned(),
                ProfileFacet {
                    mode: ProfileFacetMode::Whitelist,
                    selected: BTreeSet::from(["x".to_owned()]),
                },
            )]
            .into(),
            view_filter: ProfileViewFilter::All,
            human_only: false,
        },
    );
    model.load_profile("old").unwrap();
    assert_eq!(model.tree_order, [Attribute::Host, Attribute::Name]);
    assert!(model.facets.is_empty());
    assert!(!model.profile_dirty());
}

#[test]
fn search_summary_counts_matches_hidden_by_each_filter() {
    let mut model = mixed_model();
    assert_eq!(model.search_summary(), None);
    model.search = "key".into();
    assert_eq!(
        model.search_summary().unwrap(),
        SearchSummary {
            matches: 2,
            ..Default::default()
        }
    );
    model.filter = ViewFilter::Keys;
    let mut facet = model.facet(Attribute::User);
    facet.mode = FacetMode::Blacklist;
    facet.selected = BTreeSet::from(["alice".to_owned()]);
    model.set_facet(Attribute::User, facet);
    let summary = model.search_summary().unwrap();
    assert_eq!(
        summary,
        SearchSummary {
            matches: 2,
            hidden: 2,
            hidden_by_type: 2,
            hidden_by_audience: 0,
            hidden_by_facets: 1,
        }
    );
    assert_eq!(
        summary.text(),
        "2 matches · 2 hidden by filters (2 type, 1 attribute filters)"
    );
}
