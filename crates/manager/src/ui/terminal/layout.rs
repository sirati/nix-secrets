use ratatui::layout::Rect;

pub(super) struct Regions {
    pub filters: Rect,
    pub tree: Rect,
    pub selected: Rect,
    pub status: Rect,
    pub keys: Rect,
}

pub(super) fn regions(area: Rect, selected_lines: u16) -> Regions {
    let (filters, selected, status, keys) = if area.height >= 17 {
        (
            if area.width < 70 { 6 } else { 4 },
            (selected_lines + 2).max(3),
            3,
            if area.width < 70 { 3 } else { 4 },
        )
    } else if area.height >= 12 {
        (if area.width < 70 { 6 } else { 4 }, 0, 2, 2)
    } else {
        (
            area.height.min(3),
            0,
            0,
            area.height.saturating_sub(3).min(2),
        )
    };
    let filters = filters.min(area.height);
    let available = area.height - filters;
    let keys = keys.min(available);
    let available = available - keys;
    let status = status.min(available);
    let available = available - status;
    let selected = selected.min(available.saturating_sub(3));
    let tree = available - selected;
    let at = |offset, height| Rect {
        x: area.x,
        y: area.y + offset,
        width: area.width,
        height,
    };
    Regions {
        filters: at(0, filters),
        tree: at(filters, tree),
        selected: at(filters + tree, selected),
        status: at(filters + tree + selected, status),
        keys: at(filters + tree + selected + status, keys),
    }
}
