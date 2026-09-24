use super::*;
use buttons::{draw_rows, Button};

pub(super) fn render_filters(
    frame: &mut ratatui::Frame<'_>,
    model: &Model,
    area: Rect,
    hits: &mut HitMap,
) {
    if area.height == 0 {
        return;
    }
    frame.render_widget(
        Block::default()
            .title("Filters · 1–7 select")
            .borders(Borders::ALL),
        area,
    );
    let choice = |key, label, active| Button::new(label, MouseTarget::Filter(key)).active(active);
    let required = choice(
        1,
        "1 Required",
        model.filter == crate::model::ViewFilter::Required,
    );
    let all = choice(2, "2 All", model.filter == crate::model::ViewFilter::All);
    let keys = choice(3, "3 Keys", model.filter == crate::model::ViewFilter::Keys);
    let passwords = choice(
        4,
        "4 Passwords",
        model.filter == crate::model::ViewFilter::Passwords,
    );
    let public = choice(
        5,
        if area.width < 70 {
            "5 Public"
        } else {
            "5 Public info"
        },
        model.filter == crate::model::ViewFilter::PublicInfo,
    );
    let everyone = choice(6, "6 Everyone", !model.human_only);
    let human = choice(
        7,
        if area.width < 70 {
            "7 Human"
        } else {
            "7 Human-facing"
        },
        model.human_only,
    );
    let rows = if area.width < 70 {
        vec![
            vec![required, all, keys],
            vec![passwords, public],
            vec![everyone, human],
        ]
    } else {
        vec![
            vec![required, all, keys, passwords, public],
            vec![everyone, human],
        ]
    };
    draw_rows(frame, area, rows, model.hover, hits);
}
