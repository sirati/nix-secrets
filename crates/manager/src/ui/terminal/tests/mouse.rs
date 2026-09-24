use super::*;

fn sample_model() -> Model {
    let mut model = Model::new(vec![
        Row {
            depth: 0,
            name: "host".into(),
            display_segments: vec!["host".into()],
            path: None,
            is_set: false,
            is_task: false,
            can_generate: false,
            can_copy_public: false,
            output_is_set: None,
            description: None,
            category: crate::tree::RowCategory::Branch,
            human_facing: false,
            external_input_required: false,
        },
        Row {
            depth: 1,
            name: "services".into(),
            display_segments: vec!["host".into(), "services".into()],
            path: None,
            is_set: false,
            is_task: false,
            can_generate: false,
            can_copy_public: false,
            output_is_set: None,
            description: None,
            category: crate::tree::RowCategory::Branch,
            human_facing: false,
            external_input_required: false,
        },
        Row {
            depth: 2,
            name: "forgejo".into(),
            display_segments: vec!["host".into(), "services".into(), "forgejo".into()],
            path: None,
            is_set: false,
            is_task: false,
            can_generate: false,
            can_copy_public: false,
            output_is_set: None,
            description: None,
            category: crate::tree::RowCategory::Branch,
            human_facing: false,
            external_input_required: false,
        },
        Row {
            depth: 3,
            name: "backup".into(),
            display_segments: vec![
                "host".into(),
                "services".into(),
                "forgejo".into(),
                "backup".into(),
            ],
            path: None,
            is_set: false,
            is_task: false,
            can_generate: false,
            can_copy_public: false,
            output_is_set: None,
            description: None,
            category: crate::tree::RowCategory::Branch,
            human_facing: false,
            external_input_required: false,
        },
        Row {
            depth: 4,
            name: "password".into(),
            display_segments: vec![
                "host".into(),
                "services".into(),
                "forgejo".into(),
                "backup".into(),
                "password".into(),
            ],
            path: Some("host.services.backup-forgejo.password".into()),
            is_set: false,
            is_task: false,
            can_generate: true,
            can_copy_public: false,
            output_is_set: None,
            description: Some("A Unicode 🦀 explanation that may need shortening".into()),
            category: crate::tree::RowCategory::Password,
            human_facing: false,
            external_input_required: true,
        },
    ]);
    model.selected = model.visible_tree_rows().len() - 1;
    model
}

#[test]
fn selected_pane_uses_display_ancestry_and_ellipsizes_only_explanation() {
    let model = sample_model();
    let wide = selected_text(&model, 120);
    assert!(
        wide.starts_with("host > services > forgejo/backup/password (password) - A Unicode 🦀"),
        "{wide}"
    );
    assert!(!wide.contains("backup-forgejo"));
    assert_eq!(wide.lines().count(), 1);
    let narrow = selected_text(&model, 20);
    assert!(narrow.contains("host"));
    assert!(narrow.lines().count() > 1);
    assert_eq!(
        narrow
            .replace('\n', "")
            .split(" (password)")
            .next()
            .unwrap(),
        "host > services > forgejo/backup/password"
    );
    assert!(selected_text(&model, 66).ends_with('…'));
    let mut terminal = Terminal::new(TestBackend::new(40, 20)).unwrap();
    terminal
        .draw(|frame| {
            render(frame, &model);
        })
        .unwrap();
    let screen = (0..20)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(screen.contains("host > services > forgejo/backup/"));
    assert!(screen.contains("ord (password)"), "{screen}");
}

#[test]
fn mouse_hits_match_rendered_controls_and_modal_takes_priority() {
    let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
    let mut model = sample_model();
    let mut hits = HitMap::default();
    terminal.draw(|frame| hits = render(frame, &model)).unwrap();
    for target in [
        MouseTarget::Filter(2),
        MouseTarget::Tree(model.selected),
        MouseTarget::Shortcut(Shortcut::Character('?')),
    ] {
        let rect = hits
            .regions
            .iter()
            .find(|(_, found)| *found == target)
            .unwrap()
            .0;
        assert_eq!(hits.get(rect.x, rect.y), Some(target));
        model.hover = Some(target);
        terminal
            .draw(|frame| {
                render(frame, &model);
            })
            .unwrap();
        assert_eq!(
            terminal.backend().buffer()[(rect.x, rect.y)].bg,
            Color::Rgb(70, 75, 85)
        );
    }
    model.message = Some("Saved".into());
    terminal.draw(|frame| hits = render(frame, &model)).unwrap();
    assert!(hits
        .regions
        .iter()
        .all(|(_, target)| matches!(target, MouseTarget::Shortcut(Shortcut::Enter))));
    let mut narrow = Terminal::new(TestBackend::new(40, 20)).unwrap();
    model.message = None;
    narrow.draw(|frame| hits = render(frame, &model)).unwrap();
    assert!(hits
        .regions
        .iter()
        .any(|(_, target)| *target == MouseTarget::Filter(7)));
    assert!(hits
        .regions
        .iter()
        .any(|(_, target)| *target == MouseTarget::Tree(model.selected)));
}
