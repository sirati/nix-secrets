//! The deployment dialog renders groups with their colours, only valid
//! buttons, and fits small and large terminals.
use super::*;
use crate::model::ApprovalRequest;
use ratatui::backend::TestBackend;
use ratatui::style::Modifier;
use ratatui::Terminal;

fn ns1_request() -> ApprovalRequest {
    let id = |name: &str| format!("ns1.services.{name}");
    ApprovalRequest {
        id: "deploy-1".into(),
        target: "ns1".into(),
        create: vec![
            id("authoritative-dns.transfer-key"),
            id("authoritative-dns.zone-key"),
        ],
        replace: vec![id("authoritative-dns.tsig")],
        recipient_keys: vec!["IT Secrets".into()],
        host_key: None,
        tasks: vec![],
        generate: vec![(id("authoritative-dns.transfer-key"), "32 random bytes, base64".into())],
        missing: vec![
            (id("authoritative-dns.dyndns-update-key"), "generateOnDeploy = false".into()),
            (id("report-authorized.fault"), "filled when hetzner2 deploy".into()),
            (
                id("authoritative-dns.update-key"),
                "derived from unset hetzner2.services.stalwart.dns-update-key; deploy hetzner2 first, which generates it".into(),
            ),
        ],
        derived: vec![],
        skippable: vec![
            id("authoritative-dns.dyndns-update-key"),
            id("report-authorized.fault"),
            id("authoritative-dns.update-key"),
        ],
        missing_kinds: [
            (id("authoritative-dns.dyndns-update-key"), "Needs input"),
            (id("report-authorized.fault"), "Filled by another host"),
            (id("authoritative-dns.update-key"), "Derived from unset source"),
        ]
        .into_iter()
        .map(|(id, kind)| (id, kind.to_owned()))
        .collect(),
        host_default: vec![id("backup-public-info.storage-box-known-hosts")],
        allow_partial: false,
        ..Default::default()
    }
}

fn draw(model: &Model, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| {
        render(frame, model);
    }).unwrap();
    terminal
}

fn screen(terminal: &Terminal<TestBackend>) -> String {
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The style of the first cell of `text` on screen.
fn style_of(terminal: &Terminal<TestBackend>, text: &str) -> ratatui::style::Style {
    let buffer = terminal.backend().buffer();
    for y in 0..buffer.area.height {
        let row = (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>();
        if let Some(byte) = row.find(text) {
            let x = row[..byte].chars().count() as u16;
            return buffer[(x, y)].style();
        }
    }
    panic!("{text:?} is not on screen:\n{}", screen(terminal));
}

#[test]
fn nothing_deployable_shows_only_dismiss_in_red() {
    let mut request = ns1_request();
    request.create.clear();
    request.replace.clear();
    request.generate.clear();
    let mut model = Model::new(vec![]);
    model.mode = Mode::Approval(request);
    let terminal = draw(&model, 110, 40);
    let text = screen(&terminal);
    assert!(text.contains("Deploy ns1 · nothing can be deployed yet"), "{text}");
    assert_eq!(style_of(&terminal, "Nothing of ns1").fg, Some(Color::Red));
    assert!(!text.contains("y Deploy") && !text.contains("Approve"), "{text}");
    assert!(text.contains("n Dismiss"), "{text}");
}

#[test]
fn the_host_key_step_says_nothing_is_decrypted() {
    let mut request = ns1_request();
    request.host_key = Some("UNKNOWN SSH HOST KEY for ns1 (ns1.lamk.eu:22): ssh-ed25519 SHA256:abc".into());
    let mut model = Model::new(vec![]);
    model.mode = Mode::Approval(request);
    let terminal = draw(&model, 100, 30);
    let text = screen(&terminal);
    assert!(text.contains("Deploy ns1 · step 1/3: verify the SSH host key"), "{text}");
    assert!(text.contains("Nothing is decrypted in this step"), "{text}");
    assert!(text.contains("y Trust and connect") && text.contains("n Cancel"), "{text}");
    assert_eq!(style_of(&terminal, "UNKNOWN SSH HOST KEY").fg, Some(Color::Yellow));
}

#[test]
fn details_show_full_identifiers() {
    let mut model = Model::new(vec![]);
    model.mode = Mode::Approval(ns1_request());
    model.approval_details = true;
    let text = screen(&draw(&model, 120, 50));
    assert!(text.contains("ns1.services.report-authorized.fault"), "{text}");
    assert!(text.contains("d Summary"), "{text}");
}

#[test]
fn the_result_names_what_was_generated_and_what_was_left_out() {
    let notice = crate::ui::drive::deployed_notice(
        &["ns1.services.a.pw".into()],
        &["ns1.services.a.key".into()],
    );
    assert!(notice.contains("generated") && notice.contains("ns1.services.a.pw"), "{notice}");
    assert!(notice.contains("ns1.services.a.key"), "{notice}");
}

#[test]
fn sections_have_checked_boxes_and_missing_values_have_none() {
    for (width, height) in [(100, 40), (160, 50)] {
        let mut model = Model::new(vec![]);
        model.mode = Mode::Approval(ns1_request());
        let terminal = draw(&model, width, height);
        let text = screen(&terminal);
        assert!(text.contains("Deploy ns1 · step 2/3: choose what to deploy"), "{text}");
        assert!(text.contains("Will be sent (2/2)"), "{text}");
        assert!(text.contains("Will be generated on the target (1/1)"), "{text}");
        assert!(text.contains("[x] ▸ services.authoritative-dns.zone-key"), "{text}");
        assert!(text.contains("[x] services.authoritative-dns.tsig"), "{text}");
        assert!(text.contains("[x] services.authoritative-dns.transfer-key"), "{text}");
        assert!(text.contains("Missing (3)"), "{text}");
        assert!(text.contains("Needs input (1)"), "{text}");
        assert!(text.contains("Filled by another host (1)"), "{text}");
        assert!(text.contains("Derived from unset source (1)"), "{text}");
        // A missing row has no checkbox.
        for line in text.lines().filter(|line| line.contains("report-authorized.fault")) {
            assert!(!line.contains('['), "{line}");
        }
        assert!(text.contains("filled when hetzner2 deploy"), "{text}");
        assert_eq!(style_of(&terminal, "Missing (3)").fg, Some(Color::Yellow));
        assert!(style_of(&terminal, "Missing (3)").add_modifier.contains(Modifier::BOLD));
        assert!(style_of(&terminal, "generateOnDeploy").add_modifier.contains(Modifier::DIM));
        assert_eq!(style_of(&terminal, "Will be generated").fg, Some(Color::Cyan));
        assert_eq!(style_of(&terminal, "Will be sent").fg, Some(Color::Green));
        assert!(text.contains("Decrypt with IT Secrets"), "{text}");
        assert!(text.contains("y Deploy") && text.contains("n Reject"), "{text}");
    }
}

#[test]
fn space_a_and_clicks_toggle_rows_and_sections() {
    let mut request = ns1_request();
    let rows = request.rows();
    assert_eq!(rows.len(), 3);
    request.toggle(&rows[0].identifier);
    assert_eq!(request.checked().len(), 2);
    request.toggle_section(crate::model::Section::Sent);
    assert_eq!(request.checked().len(), 3, "a partly unchecked section is checked whole");
    request.toggle_section(crate::model::Section::Sent);
    assert_eq!(request.checked().len(), 1);
    assert!(request.deployable());
    request.toggle(&rows[2].identifier);
    assert!(!request.deployable(), "nothing checked, nothing to deploy");
    // Through the reducer: Space on the cursor row, a on its section, and a
    // click on a label.
    let mut model = Model::new(vec![]);
    model.mode = Mode::Approval(ns1_request());
    let mut writer = super::tests::NoWriter;
    crate::ui::reduce(&mut model, UiEvent::Character(' '), &mut writer);
    let Mode::Approval(request) = &model.mode else { panic!() };
    assert!(request.unchecked.contains(&rows[0].identifier));
    crate::ui::reduce(&mut model, UiEvent::Down, &mut writer);
    crate::ui::reduce(&mut model, UiEvent::Character('a'), &mut writer);
    let Mode::Approval(request) = &model.mode else { panic!() };
    assert!(request.unchecked.is_empty(), "{:?}", request.unchecked);
    let terminal = draw(&model, 120, 40);
    let text = screen(&terminal);
    assert!(text.contains("[x] ▸ services.authoritative-dns.tsig"), "{text}");
    crate::ui::reduce(&mut model, UiEvent::Click(MouseTarget::DeployRow(2)), &mut writer);
    let Mode::Approval(request) = &model.mode else { panic!() };
    assert!(request.unchecked.contains(&rows[2].identifier));
    let text = screen(&draw(&model, 120, 40));
    assert!(text.contains("Will be generated on the target (0/1)"), "{text}");
    assert!(text.contains("[ ] ▸ services.authoritative-dns.transfer-key"), "{text}");
}

#[test]
fn a_click_anywhere_on_a_row_hits_its_checkbox() {
    let mut model = Model::new(vec![]);
    model.mode = Mode::Approval(ns1_request());
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    let mut hits = None;
    terminal.draw(|frame| hits = Some(render(frame, &model))).unwrap();
    let hits = hits.unwrap();
    let buffer = terminal.backend().buffer();
    let (x, y) = (0..buffer.area.height)
        .find_map(|y| {
            let row = (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>();
            row.find("authoritative-dns.tsig").map(|byte| (row[..byte].chars().count() as u16 + 3, y))
        })
        .unwrap();
    assert_eq!(hits.get(x, y), Some(MouseTarget::DeployRow(1)));
}

/// No row's identifier is ever cut, at any common terminal size; the body
/// scrolls instead. This is the dialog that showed "Needs i" and "servi…".
#[test]
fn rows_keep_their_identifiers_at_80x24_120x40_and_200x60() {
    let mut request = ns1_request();
    let long = "ns1.services.backup-stalwart-relay.backup.storagebox-access-with-a-long-name";
    request.missing.push((long.into(), "…/known-hosts is absent".into()));
    request.missing_kinds.insert(long.into(), "Cannot deploy".into());
    for (width, height) in [(80, 24), (120, 40), (200, 60)] {
        for details in [false, true] {
            let mut model = Model::new(vec![]);
            model.mode = Mode::Approval(request.clone());
            model.approval_details = details;
            // Scroll through the whole body; the dialog's inner text, wrapped
            // lines joined, so an identifier wider than the screen still
            // counts when it wraps whole.
            let mut seen = String::new();
            for scroll in 0..60 {
                model.modal_scroll = scroll;
                let text = screen(&draw(&model, width, height));
                let lines = text.lines().map(|line| line.chars().collect::<Vec<_>>()).collect::<Vec<_>>();
                let (top, left) = lines
                    .iter()
                    .enumerate()
                    .find_map(|(y, line)| {
                        let row = line.iter().collect::<String>();
                        row.find("┌Deploy").map(|byte| (y, row[..byte].chars().count()))
                    })
                    .expect("the dialog is on screen");
                let right = (left + 1..lines[top].len()).find(|x| lines[top][*x] == '┐').unwrap();
                for line in &lines[top + 1..] {
                    if line[left] != '│' {
                        break;
                    }
                    let inner = line[left + 1..right].iter().collect::<String>();
                    seen.push_str(inner.trim());
                }
            }
            assert!(!seen.contains("servi…") && !seen.contains("Needs i\n"), "{width}x{height}");
            for row in request.rows().iter().map(|row| row.identifier.clone()).chain(
                request.missing.iter().map(|(identifier, _)| identifier.clone()),
            ) {
                let name = if details { row.clone() } else { row.trim_start_matches("ns1.").to_owned() };
                assert!(seen.contains(&name), "{width}x{height} details={details}: {name} cut:\n{}", screen(&draw(&model, width, height)));
            }
            for header in ["Will be sent", "Will be generated on the target", "Missing", "Cannot deploy", "Needs input"] {
                assert!(seen.contains(header), "{width}x{height}: {header}");
            }
        }
    }
}

#[test]
fn the_result_counts_sent_generated_left_out_and_missing() {
    let line = crate::ui::drive::summary_line(&crate::model::DeploySummary {
        target: "ns1".into(),
        sent: 12,
        generated: 2,
        left_out: vec!["ns1.services.a.b".into()],
        missing: vec!["x".into(), "y".into(), "z".into()],
    });
    assert!(line.starts_with("Deploy ns1 · step 3/3 done: 12 sent · 2 generated · 1 left out · 3 missing"), "{line}");
    assert!(line.contains("Left out by you: ns1.services.a.b"), "{line}");
}
