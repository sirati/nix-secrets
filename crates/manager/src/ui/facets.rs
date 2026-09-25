use super::*;
use crate::model::{Attribute, FacetMode};

pub(super) fn reduce(model: &mut Model, mode: Mode, event: UiEvent) {
    match mode {
        Mode::FacetCategories { mut selected } => {
            selected = moved(selected, &event, Attribute::GROUPING.len());
            model.mode = match event {
                UiEvent::Enter => Mode::FacetValues {
                    attribute: Attribute::GROUPING[selected],
                    selected: 0,
                },
                UiEvent::Escape => Mode::Browse,
                _ => Mode::FacetCategories { selected },
            };
        }
        Mode::FacetValues {
            attribute,
            mut selected,
        } => {
            let values = model
                .facet_values(attribute)
                .into_iter()
                .collect::<Vec<_>>();
            selected = moved(selected, &event, values.len() + 3);
            model.mode = match event {
                UiEvent::Enter if selected < 3 => {
                    let mode = match selected {
                        0 => FacetMode::All,
                        1 => FacetMode::Whitelist,
                        _ => FacetMode::Blacklist,
                    };
                    let mut facet = model.facet(attribute);
                    facet.set_mode(mode, &values.iter().cloned().collect());
                    model.set_facet(attribute, facet);
                    Mode::FacetValues {
                        attribute,
                        selected,
                    }
                }
                UiEvent::Enter if selected - 3 < values.len() => {
                    let value = values[selected - 3].clone();
                    let mut facet = model.facet(attribute);
                    if facet.mode == FacetMode::All {
                        Mode::FacetFirstChoice { attribute, value }
                    } else {
                        facet.toggle(&value);
                        model.set_facet(attribute, facet);
                        Mode::FacetValues {
                            attribute,
                            selected,
                        }
                    }
                }
                UiEvent::Escape => Mode::FacetCategories {
                    selected: Attribute::GROUPING
                        .iter()
                        .position(|item| *item == attribute)
                        .unwrap_or(0),
                },
                _ => Mode::FacetValues {
                    attribute,
                    selected,
                },
            };
        }
        Mode::FacetFirstChoice { attribute, value } => {
            if let UiEvent::Character(choice @ ('1'..='4')) = event {
                let universe = model.facet_values(attribute);
                let mut facet = model.facet(attribute);
                match choice {
                    '1' => {
                        facet.mode = FacetMode::Whitelist;
                        facet.selected = [value].into();
                    }
                    '2' => {
                        facet.mode = FacetMode::Blacklist;
                        facet.selected = [value].into();
                    }
                    '3' => {
                        facet.mode = FacetMode::Whitelist;
                        facet.selected =
                            universe.into_iter().filter(|item| item != &value).collect();
                    }
                    '4' => {
                        facet.mode = FacetMode::Blacklist;
                        facet.selected =
                            universe.into_iter().filter(|item| item != &value).collect();
                    }
                    _ => unreachable!(),
                }
                model.set_facet(attribute, facet);
                model.mode = Mode::FacetValues {
                    attribute,
                    selected: 0,
                };
            } else {
                model.mode = match event {
                    UiEvent::Escape => Mode::FacetValues {
                        attribute,
                        selected: 0,
                    },
                    _ => Mode::FacetFirstChoice { attribute, value },
                };
            }
        }
        Mode::TreeOrder { mut selected } => {
            let attrs = model.tree_editor_attributes();
            selected = moved(selected, &event, attrs.len());
            model.mode = match event {
                UiEvent::Character(' ') => {
                    let attribute = attrs[selected];
                    if let Some(position) =
                        model.tree_order.iter().position(|item| *item == attribute)
                    {
                        model.tree_order.remove(position);
                    } else {
                        model.tree_order.push(attribute);
                    }
                    model.rebuild_tree();
                    Mode::TreeOrder {
                        selected: model
                            .tree_editor_attributes()
                            .iter()
                            .position(|item| *item == attribute)
                            .unwrap_or(0),
                    }
                }
                UiEvent::Character('[' | ']') => {
                    let attribute = attrs[selected];
                    if let Some(position) =
                        model.tree_order.iter().position(|item| *item == attribute)
                    {
                        let next = if event == UiEvent::Character('[') {
                            position.saturating_sub(1)
                        } else {
                            (position + 1).min(model.tree_order.len() - 1)
                        };
                        model.tree_order.swap(position, next);
                        model.rebuild_tree();
                    }
                    Mode::TreeOrder {
                        selected: model
                            .tree_editor_attributes()
                            .iter()
                            .position(|item| *item == attribute)
                            .unwrap_or(0),
                    }
                }
                UiEvent::Escape | UiEvent::Enter => Mode::Browse,
                _ => Mode::TreeOrder { selected },
            };
        }
        _ => unreachable!(),
    }
}

fn moved(current: usize, event: &UiEvent, count: usize) -> usize {
    match event {
        UiEvent::Up => current.saturating_sub(1),
        UiEvent::Down => (current + 1).min(count.saturating_sub(1)),
        _ => current.min(count.saturating_sub(1)),
    }
}
