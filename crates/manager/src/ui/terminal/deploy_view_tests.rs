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
fn missing_values_are_listed_by_reason_in_colour_and_the_rest_deploys() {
    for (width, height) in [(100, 40), (160, 50)] {
        let mut model = Model::new(vec![]);
        model.mode = Mode::Approval(ns1_request());
        let terminal = draw(&model, width, height);
        let text = screen(&terminal);
        assert!(text.contains("Deploy ns1 · step 2/2: review what will be deployed"), "{text}");
        assert!(text.contains("3 values cannot be deployed yet"), "{text}");
        assert!(text.contains("Needs input (1)"), "{text}");
        assert!(text.contains("Filled by another host (1)"), "{text}");
        assert!(text.contains("Derived from unset source (1)"), "{text}");
        assert!(text.contains("Uses the host's default (1)"), "{text}");
        // One row per value, under the host header, with its reason.
        assert!(text.contains("services.report-authorized.fault"), "{text}");
        assert!(text.contains("filled when hetzner2 deploy"), "{text}");
        assert_eq!(style_of(&terminal, "Needs input (1)").fg, Some(Color::Yellow));
        assert!(style_of(&terminal, "Needs input (1)").add_modifier.contains(Modifier::BOLD));
        assert_eq!(style_of(&terminal, "services.authoritative-dns.dyndns").fg, Some(Color::Yellow));
        assert!(style_of(&terminal, "generateOnDeploy").add_modifier.contains(Modifier::DIM));
        assert_eq!(style_of(&terminal, "Will be generated").fg, Some(Color::Cyan));
        assert_eq!(style_of(&terminal, "Will be replaced").fg, Some(Color::Green));
        // Missing values are not listed as set.
        assert!(text.contains("Will be set (1)"), "{text}");
        assert!(text.contains("y Deploy") && text.contains("n Reject"), "{text}");
        assert!(text.contains("d Details"), "{text}");
        assert!(text.contains("partial deployment is safe"), "{text}");
    }
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
    assert!(text.contains("Deploy ns1 · step 1/2: verify the SSH host key"), "{text}");
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
