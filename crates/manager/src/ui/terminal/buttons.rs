use super::*;
use ratatui::style::Modifier;

#[derive(Clone)]
pub(super) struct Button {
    pub label: &'static str,
    pub target: MouseTarget,
    pub active: bool,
    pub enabled: bool,
}

impl Button {
    pub fn new(label: &'static str, target: MouseTarget) -> Self {
        Self {
            label,
            target,
            active: false,
            enabled: true,
        }
    }
    pub fn active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

pub(super) fn draw_rows(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    rows: Vec<Vec<Button>>,
    hover: Option<MouseTarget>,
    hits: &mut HitMap,
) {
    let mut lines = Vec::new();
    let inner_width = area.width.saturating_sub(2);
    let max_rows = area.height.saturating_sub(2) as usize;
    for (row_index, buttons) in rows.into_iter().take(max_rows).enumerate() {
        let mut spans = Vec::new();
        let mut x = 0_u16;
        for button in buttons {
            let label = format!(" {} ", button.label);
            let width = label.chars().count() as u16;
            if x > 0 {
                x += 1;
                spans.push(Span::raw(" "));
            }
            if x + width > inner_width {
                break;
            }
            let mut style = if button.active {
                Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else if button.enabled {
                Style::default().fg(Color::Cyan).bg(Color::DarkGray)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            if button.enabled && hover == Some(button.target) {
                style = style.bg(Color::Rgb(70, 75, 85));
            }
            spans.push(Span::styled(label, style));
            if button.enabled {
                hits.add(
                    Rect {
                        x: area.x + 1 + x,
                        y: area.y + 1 + row_index as u16,
                        width,
                        height: 1,
                    },
                    button.target,
                );
            }
            x += width;
        }
        lines.push(Line::from(spans));
    }
    frame.render_widget(
        Paragraph::new(lines),
        area.inner(ratatui::layout::Margin {
            horizontal: 1,
            vertical: 1,
        }),
    );
}

pub(super) fn wrap_buttons(buttons: Vec<Button>, width: u16, max_rows: usize) -> Vec<Vec<Button>> {
    let mut rows = vec![Vec::new()];
    let mut used = 0_usize;
    for button in buttons {
        let len = button.label.chars().count() + 2;
        if used > 0 && used + 1 + len > width as usize {
            if rows.len() >= max_rows {
                break;
            }
            rows.push(Vec::new());
            used = 0;
        }
        if len > width as usize {
            continue;
        }
        used += (used > 0) as usize + len;
        rows.last_mut().unwrap().push(button);
    }
    rows
}
