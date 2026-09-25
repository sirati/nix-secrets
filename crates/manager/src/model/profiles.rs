use super::*;
use nix_secrets_core::{ProfileFacet, ProfileFacetMode, ProfileViewFilter, ViewProfile};

impl Model {
    pub fn capture_profile(&self) -> ViewProfile {
        ViewProfile {
            tree_order: self
                .tree_order
                .iter()
                .map(|attribute| attribute.key().into())
                .collect(),
            facets: self
                .facets
                .iter()
                .filter(|(_, facet)| facet.mode != FacetMode::All)
                .map(|(attribute, facet)| {
                    (
                        attribute.key().into(),
                        ProfileFacet {
                            mode: match facet.mode {
                                FacetMode::All => ProfileFacetMode::All,
                                FacetMode::Whitelist => ProfileFacetMode::Whitelist,
                                FacetMode::Blacklist => ProfileFacetMode::Blacklist,
                            },
                            selected: facet.selected.clone(),
                        },
                    )
                })
                .collect(),
            view_filter: match self.filter {
                ViewFilter::Required => ProfileViewFilter::Required,
                ViewFilter::All => ProfileViewFilter::All,
                ViewFilter::Keys => ProfileViewFilter::Keys,
                ViewFilter::Passwords => ProfileViewFilter::Passwords,
                ViewFilter::PublicInfo => ProfileViewFilter::PublicInfo,
            },
            human_only: self.human_only,
        }
    }

    pub fn load_profile(&mut self, name: &str) -> Result<(), String> {
        let profile = self
            .profiles
            .profiles
            .get(name)
            .ok_or("profile no longer exists")?
            .clone();
        profile.validate().map_err(|error| error.to_string())?;
        self.tree_order = profile
            .tree_order
            .iter()
            .map(|value| {
                Attribute::from_key(value).ok_or_else(|| format!("unknown tree attribute: {value}"))
            })
            // Older profiles may group by explanation, which is no longer offered.
            .filter(|attribute| attribute.as_ref().map_or(true, |item| item.groups()))
            .collect::<Result<_, _>>()?;
        self.facets = profile
            .facets
            .iter()
            .map(|(attribute, facet)| {
                let attribute = Attribute::from_key(attribute).ok_or("unknown facet attribute")?;
                Ok(attribute.groups().then(|| {
                    (
                        attribute,
                        Facet {
                            mode: match facet.mode {
                                ProfileFacetMode::All => FacetMode::All,
                                ProfileFacetMode::Whitelist => FacetMode::Whitelist,
                                ProfileFacetMode::Blacklist => FacetMode::Blacklist,
                            },
                            selected: facet.selected.clone(),
                        },
                    )
                }))
            })
            .filter_map(Result::transpose)
            .collect::<Result<_, &str>>()
            .map_err(str::to_owned)?;
        self.filter = match profile.view_filter {
            ProfileViewFilter::Required => ViewFilter::Required,
            ProfileViewFilter::All => ViewFilter::All,
            ProfileViewFilter::Keys => ViewFilter::Keys,
            ProfileViewFilter::Passwords => ViewFilter::Passwords,
            ProfileViewFilter::PublicInfo => ViewFilter::PublicInfo,
        };
        self.human_only = profile.human_only;
        self.search.clear();
        self.active_profile = Some(name.into());
        self.rebuild_tree();
        Ok(())
    }

    pub fn profile_dirty(&self) -> bool {
        self.active_profile.as_ref().is_some_and(|name| {
            self.profiles.profiles.get(name).map(normalized) != Some(self.capture_profile())
        })
    }
}

/// A stored profile without attributes that no longer group, so a profile
/// saved with `explanation` does not read as modified right after loading.
fn normalized(profile: &ViewProfile) -> ViewProfile {
    let groups = |key: &String| Attribute::from_key(key).is_some_and(Attribute::groups);
    let mut profile = profile.clone();
    profile.tree_order.retain(groups);
    profile
        .facets
        .retain(|key, facet| groups(key) && facet.mode != ProfileFacetMode::All);
    profile
}
