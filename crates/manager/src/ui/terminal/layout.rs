use ratatui::layout::Rect;

pub(super) struct Regions {
    pub filters: Rect,
    pub tree: Rect,
    pub selected: Rect,
    pub status: Rect,
    pub keys: Rect,
    /// The procedure task bar, above the actions; empty without procedures.
    pub taskbar: Rect,
}

#[cfg(test)]
pub(super) fn regions(area: Rect, selected_lines: u16) -> Regions {
    regions_with_taskbar(area, selected_lines, 0)
}

/// Like [`regions`], with room for `procedures` task bar entries: one
/// bordered line each, up to three, on a tall screen; one plain line on a
/// short one.
pub(super) fn regions_with_taskbar(area: Rect, selected_lines: u16, procedures: u16) -> Regions {
    let taskbar = match procedures {
        0 => 0,
        count if area.height >= 17 => count.min(3) + 2,
        _ if area.height >= 12 => 1,
        _ => 0,
    };
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
    let taskbar = taskbar.min(available.saturating_sub(3));
    let available = available - taskbar;
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
        taskbar: at(filters + tree + selected + status, taskbar),
        keys: at(filters + tree + selected + status + taskbar, keys),
    }
}

/// The width of an ordinary dialog whose content needs no more.
pub(super) const DIALOG_WIDTH: u16 = 80;
/// The narrowest padded box when the terminal is wide enough.
const MIN_WIDTH: u16 = 64;
/// Below this many rows inside the margin, a box may use every row.
const MIN_HEIGHT: u16 = 12;

/// Cells wide for a 4:3 box on screen of `height` rows. Terminal cells are
/// about twice as tall as wide, so 4:3 on screen is 8:3 in cells.
fn wide_for(height: u16) -> u16 {
    (u32::from(height) * 8 / 3).min(u32::from(u16::MAX)) as u16
}

/// Rows high for a 4:3 box on screen of `width` cells.
fn high_for(width: u16) -> u16 {
    (u32::from(width) * 3).div_ceil(8) as u16
}

/// Where a dialog goes. `natural_width` is the width, borders included, at
/// which no line of its content wraps, and `height_at(width)` the height
/// its content needs in a box that wide.
///
/// An ordinary dialog is [`DIALOG_WIDTH`] wide and only grows wider while
/// its content is taller than 4:3 on screen, never beyond the width at which
/// nothing wraps. A `padded` dialog, the secret request, starts at its
/// natural width (at most 4:3 of the screen's height, at least
/// [`MIN_WIDTH`]) and is made taller to about 4:3 on screen.
///
/// Both keep a margin of two columns, and a padded dialog one row. A
/// terminal with less than [`MIN_WIDTH`] or [`MIN_HEIGHT`] inside that margin
/// is used fully in that direction instead, and the body scrolls.
pub(super) fn dialog_area(
    area: Rect,
    natural_width: u16,
    padded: bool,
    height_at: impl Fn(u16) -> u16,
) -> Rect {
    let room_width = match area.width.saturating_sub(4) {
        room if room < MIN_WIDTH => area.width,
        room => room,
    };
    let room_height = match area.height.saturating_sub(2) {
        // Ordinary dialogs keep using every row, as they always have.
        _ if !padded => area.height,
        room if room < MIN_HEIGHT => area.height,
        room => room,
    };
    let mut width = if padded {
        natural_width
            .min(wide_for(room_height))
            .max(MIN_WIDTH)
            .min(room_width)
    } else {
        area.width.min(DIALOG_WIDTH)
    };
    // Content taller than 4:3 widens the box while that saves wrapped lines.
    let limit = room_width.min(natural_width.max(width));
    while width < limit && width < wide_for(height_at(width).min(room_height)) {
        width = (width + 4).min(limit);
    }
    let content = height_at(width);
    let height = if padded {
        content.max(high_for(width))
    } else {
        content
    };
    let height = height.min(room_height).max(1);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}
