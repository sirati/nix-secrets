use super::*;

#[derive(Default)]
pub(super) struct HitMap {
    pub regions: Vec<(Rect, MouseTarget)>,
}

impl HitMap {
    pub fn add(&mut self, rect: Rect, target: MouseTarget) {
        if rect.width > 0 && rect.height > 0 {
            self.regions.push((rect, target));
        }
    }

    pub fn get(&self, x: u16, y: u16) -> Option<MouseTarget> {
        self.regions
            .iter()
            .rev()
            .find_map(|(rect, target)| rect.contains((x, y).into()).then_some(*target))
    }
}
