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
            identity: None,
            presentation: None,
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
            identity: None,
            presentation: None,
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
            identity: None,
            presentation: None,
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
            identity: None,
            presentation: None,
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
            identity: None,
            presentation: None,
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
        wide.starts_with("host > services > forgejo/backup/password (passphrase) - A Unicode 🦀"),
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
            .split(" (passphrase)")
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
    assert!(screen.contains("ord (passphrase)"), "{screen}");
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
        MouseTarget::Shortcut(Shortcut::Character('F')),
        MouseTarget::Shortcut(Shortcut::Character('T')),
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
    model.fail("Save failed");
    terminal.draw(|frame| hits = render(frame, &model)).unwrap();
    assert!(hits
        .regions
        .iter()
        .all(|(_, target)| matches!(target, MouseTarget::Shortcut(Shortcut::Enter))));
    model.acknowledge();
    model.inform("Saved");
    terminal.draw(|frame| hits = render(frame, &model)).unwrap();
    let tree = hits
        .regions
        .iter()
        .find(|(_, target)| *target == MouseTarget::Tree(model.selected))
        .unwrap()
        .0;
    assert_eq!(
        hits.get(tree.x, tree.y),
        Some(MouseTarget::Tree(model.selected)),
        "the tree stays clickable beside a success notice"
    );
    let notice = hits
        .regions
        .iter()
        .find(|(_, target)| *target == MouseTarget::Notice)
        .unwrap()
        .0;
    assert_eq!(
        hits.get(notice.x + 1, notice.y + 1),
        Some(MouseTarget::Notice)
    );
    model.mode = Mode::DeleteConfirm {
        path: "h.services.s.key".into(),
    };
    terminal.draw(|frame| hits = render(frame, &model)).unwrap();
    assert!(
        hits.regions
            .iter()
            .all(|(_, target)| *target == MouseTarget::Notice),
        "a notice above a confirmation hides its buttons"
    );
    model.mode = Mode::Browse;
    model.acknowledge();
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

#[test]
fn facet_modal_items_are_clickable_and_hovered_without_underlying_hits() {
    let mut model = sample_model();
    model.mode = Mode::FacetCategories { selected: 0 };
    let mut terminal = Terminal::new(TestBackend::new(40, 20)).unwrap();
    let mut hits = HitMap::default();
    terminal.draw(|frame| hits = render(frame, &model)).unwrap();
    assert!(hits
        .regions
        .iter()
        .all(|(_, target)| matches!(target, MouseTarget::ModalItem(_) | MouseTarget::Shortcut(_))));
    let rect = hits
        .regions
        .iter()
        .find(|(_, target)| *target == MouseTarget::ModalItem(3))
        .unwrap()
        .0;
    assert_eq!(hits.get(rect.x, rect.y), Some(MouseTarget::ModalItem(3)));
    model.hover = Some(MouseTarget::ModalItem(3));
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

#[test]
fn property_modal_shows_semantic_facets_and_stable_storage_identifier() {
    let mut model = sample_model();
    let selected = model.visible_rows()[model.selected];
    model.rows[selected].identity = Some(nix_secrets_core::schema::SecretIdentity {
        host: "host".into(),
        scope: "system".into(),
        user: None,
        service: "forgejo".into(),
        responsibility: "backup".into(),
        namespace: Some("shared".into()),
        name: "password".into(),
    });
    model.mode = Mode::Properties { scroll: 0 };
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal
        .draw(|frame| {
            render(frame, &model);
        })
        .unwrap();
    let screen = (0..30)
        .map(|y| line(&terminal, y))
        .collect::<Vec<_>>()
        .join("\n");
    for expected in [
        "Properties",
        "Host: host",
        "System/User: system",
        "Responsibility: backup",
        "Namespace: shared",
        "Storage identifier: host.services.backup-forgejo.password",
    ] {
        assert!(screen.contains(expected), "missing {expected}: {screen}");
    }
}

struct Unused;

impl SecretWriter for Unused {
    fn write(
        &mut self,
        _path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        Err(("unused".into(), value))
    }
}

/// Renders, resolves a real screen position through the hit map as the
/// terminal frontend does, and feeds the resulting click to the reducer.
fn click_at(terminal: &mut Terminal<TestBackend>, model: &mut Model, x: u16, y: u16) {
    let mut hits = HitMap::default();
    terminal.draw(|frame| hits = render(frame, model)).unwrap();
    if let Some(target) = hits.get(x, y) {
        reduce(model, UiEvent::Click(target), &mut Unused);
    }
}

#[test]
fn click_outside_a_success_notice_closes_it_and_acts_on_the_target() {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    let mut model = sample_model();
    model.selected = 2;
    model.inform("saved");
    // Row 0 of the tree is drawn on screen line 5.
    click_at(&mut terminal, &mut model, 5, 5);
    assert!(model.message.is_none());
    assert_eq!(model.selected, 0, "the click selected the row it hit");

    model.inform("saved");
    // The F Filter button in the filter bar.
    click_at(&mut terminal, &mut model, 33, 2);
    assert!(model.message.is_none());
    assert!(matches!(model.mode, Mode::FacetCategories { .. }));

    model.mode = Mode::Browse;
    model.inform("saved");
    // Inside the notice box: only closes it.
    click_at(&mut terminal, &mut model, 50, 14);
    assert!(model.message.is_none());
    assert!(matches!(model.mode, Mode::Browse));
    assert_eq!(model.selected, 0);

    model.fail("failed");
    click_at(&mut terminal, &mut model, 5, 6);
    assert_eq!(model.message_text(), Some("failed"), "errors keep blocking");
}

fn leaf(name: &str, set: bool) -> Row {
    Row {
        depth: 0,
        name: name.into(),
        display_segments: vec![],
        path: Some(format!("h.services.s.{name}")),
        is_set: set,
        is_task: false,
        can_generate: false,
        can_copy_public: false,
        output_is_set: None,
        description: None,
        category: crate::tree::RowCategory::Other,
        human_facing: false,
        external_input_required: true,
        identity: None,
        presentation: None,
    }
}

/// Plays screen positions through the real renderer and hit map, the way the
/// terminal frontend resolves mouse events, inside the real drive loop.
struct ScreenFrontend {
    terminal: Terminal<TestBackend>,
    hits: HitMap,
    script: std::collections::VecDeque<ScreenStep>,
    /// Mode and selection as drawn just before the script ran out.
    last: Option<(bool, String, Option<String>)>,
}

enum ScreenStep {
    Event(UiEvent),
    Click(u16, u16),
}

impl Frontend for ScreenFrontend {
    fn draw(&mut self, model: &Model) -> io::Result<()> {
        self.last = Some((
            model.message.is_some(),
            format!("{:?}", model.mode),
            model.selected().and_then(|row| row.path.clone()),
        ));
        let mut hits = HitMap::default();
        self.terminal.draw(|frame| hits = render(frame, model))?;
        self.hits = hits;
        Ok(())
    }
    fn read(&mut self, timeout: std::time::Duration) -> io::Result<UiEvent> {
        // A person reacts slower than the redraw deadline.
        std::thread::sleep(timeout.min(std::time::Duration::from_millis(40)));
        let (x, y) = match self.script.pop_front() {
            None => return Err(io::Error::other("script finished")),
            Some(ScreenStep::Event(event)) => return Ok(event),
            Some(ScreenStep::Click(x, y)) => (x, y),
        };
        Ok(self
            .hits
            .get(x, y)
            .map(UiEvent::Click)
            .unwrap_or(UiEvent::Tick))
    }
}

/// Completes one save, then delivers the backend's row refresh.
struct SavingWriter {
    completions: Vec<Completion>,
    refreshed: Option<Vec<Row>>,
}

impl SecretWriter for SavingWriter {
    fn write(
        &mut self,
        _path: &str,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Action, (String, Zeroizing<Vec<u8>>)> {
        Err(("unused".into(), value))
    }
    fn poll_completion(&mut self) -> Option<Completion> {
        self.completions.pop()
    }
    fn refresh_rows(&mut self) -> Result<Option<Vec<Row>>, String> {
        Ok(self.refreshed.take())
    }
}

#[test]
fn click_on_another_unset_row_after_a_save_selects_it_and_opens_entry() {
    let rows: Vec<Row> = (0..12)
        .map(|index| leaf(&format!("item{index:02}"), false))
        .collect();
    let mut refreshed = rows.clone();
    refreshed[0].is_set = true;
    let mut model = Model::new(rows);
    model.filter = crate::model::ViewFilter::All;
    model.rebuild_tree();
    // Where item08 is drawn once the save is shown, as the user sees it.
    let line = {
        let mut probe = Model::new(refreshed.clone());
        probe.filter = crate::model::ViewFilter::All;
        probe.rebuild_tree();
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal
            .draw(|frame| {
                render(frame, &probe);
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..30)
            .find(|y| {
                (0..100)
                    .map(|x| buffer[(x, *y)].symbol())
                    .collect::<String>()
                    .contains("item08")
            })
            .unwrap()
    };
    let mut writer = SavingWriter {
        completions: vec![Completion::Saved("h.services.s.item00".into())],
        refreshed: Some(refreshed),
    };
    let mut frontend = ScreenFrontend {
        terminal: Terminal::new(TestBackend::new(100, 30)).unwrap(),
        hits: HitMap::default(),
        last: None,
        // A tick applies the save and the refresh; the click hits row 8,
        // which lies under the notice box. The final ticks let it redraw.
        script: [
            ScreenStep::Event(UiEvent::Tick),
            ScreenStep::Event(UiEvent::Refresh),
            // Column 5 is left of the notice box on item08's line.
            ScreenStep::Click(5, line),
        ]
        .into(),
    };
    for _ in 0..3 {
        frontend.script.push_back(ScreenStep::Event(UiEvent::Tick));
    }
    assert!(drive(&mut frontend, &mut writer, &mut model).is_err());
    let (notice, mode, selected) = frontend.last.unwrap();
    assert!(!notice, "the notice closed");
    assert_eq!(selected.as_deref(), Some("h.services.s.item08"));
    assert!(
        mode.starts_with("Edit"),
        "a click on an unset input value opens its entry: {mode}"
    );
}
