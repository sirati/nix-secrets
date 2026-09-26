use super::*;

pub(super) fn render_tree(
    frame: &mut ratatui::Frame<'_>,
    model: &Model,
    area: ratatui::layout::Rect,
    hits: &mut HitMap,
) {
    let visible = model.visible_tree_rows();
    let items = visible
        .iter()
        .enumerate()
        .into_iter()
        .map(|(index, visible)| {
            let row = &model.rows[visible.index];
            let mut item = item(row, visible.depth, &visible.label, model.is_collapsed(row));
            if model.hover == Some(MouseTarget::Tree(index)) {
                item = item.style(Style::default().bg(Color::Rgb(70, 75, 85)));
            }
            item
        })
        .collect::<Vec<_>>();
    let mut state =
        ListState::default().with_selected((!items.is_empty()).then_some(model.selected));
    let list = List::new(items)
        .block(Block::default().title("Secrets").borders(Borders::ALL))
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, area, &mut state);
    let inner_height = area.height.saturating_sub(2) as usize;
    for index in state.offset()..visible.len().min(state.offset() + inner_height) {
        hits.add(
            Rect {
                x: area.x + 1,
                y: area.y + 1 + (index - state.offset()) as u16,
                width: area.width.saturating_sub(2),
                height: 1,
            },
            MouseTarget::Tree(index),
        );
    }
}

fn item(row: &Row, depth: usize, name: &str, collapsed: bool) -> ListItem<'static> {
    let indent = "  ".repeat(depth);
    if !row.is_secret() {
        // ▸ marks a collapsed group, ▾ an expanded one.
        let marker = if collapsed { "▸" } else { "▾" };
        return ListItem::new(format!("{indent}{marker} {name}/"));
    }
    let (status, color) = if row.is_set {
        ("set", Color::Green)
    } else {
        ("unset", Color::Red)
    };
    let label = if row.is_task() {
        format!(
            "task · input {status} · output {}",
            row.output_is_set.map(set_status).unwrap_or("unknown")
        )
    } else {
        status.into()
    };
    ListItem::new(Line::from(vec![
        Span::raw(format!("{indent}{name}  ")),
        Span::styled(label, Style::default().fg(color)),
    ]))
}

fn set_status(set: bool) -> &'static str {
    if set {
        "set"
    } else {
        "unset"
    }
}

pub(super) fn task_status(task: &crate::model::TaskApproval) -> String {
    if task.requires_input {
        format!(
            "{} (bootstrap {}, output {})",
            task.identifier,
            set_status(task.input_is_set),
            task.output_is_set.map(set_status).unwrap_or("unknown")
        )
    } else {
        format!(
            "{} (generated on target; output {})",
            task.identifier,
            task.output_is_set.map(set_status).unwrap_or("unknown")
        )
    }
}
