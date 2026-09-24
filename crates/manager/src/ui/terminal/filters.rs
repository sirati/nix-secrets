use super::*;
use ratatui::style::Modifier;

pub(super) fn render_filters(frame: &mut ratatui::Frame<'_>, model: &Model, area: Rect) {
    if area.height == 0 {
        return;
    }
    let choice = |key, name: &'static str, selected| button(key, name, selected);
    let required = choice(
        1,
        "Required",
        model.filter == crate::model::ViewFilter::Required,
    );
    let all = choice(2, "All", model.filter == crate::model::ViewFilter::All);
    let keys = choice(3, "Keys", model.filter == crate::model::ViewFilter::Keys);
    let passwords = choice(
        4,
        "Passwords",
        model.filter == crate::model::ViewFilter::Passwords,
    );
    let public = choice(
        5,
        if area.width < 70 {
            "Public"
        } else {
            "Public info"
        },
        model.filter == crate::model::ViewFilter::PublicInfo,
    );
    let everyone = choice(6, "Everyone", !model.human_only);
    let human = choice(
        7,
        if area.width < 70 {
            "Human"
        } else {
            "Human-facing"
        },
        model.human_only,
    );
    let lines = if area.width < 70 {
        vec![
            row(vec![required, all, keys]),
            row(vec![passwords, public]),
            row(vec![everyone, human]),
        ]
    } else {
        vec![
            row(vec![required, all, keys, passwords, public]),
            row(vec![everyone, human]),
        ]
    };
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title("Filters · 1–7 select")
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn button(key: u8, label: &str, selected: bool) -> Span<'static> {
    let style = if selected {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::default().fg(Color::Cyan).bg(Color::DarkGray)
    };
    Span::styled(format!(" {key} {label} "), style)
}

fn row(buttons: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = Vec::with_capacity(buttons.len() * 2);
    for (index, button) in buttons.into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(button);
    }
    Line::from(spans)
}
