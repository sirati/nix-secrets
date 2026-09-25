//! Public, repo-local TUI view profiles. No secret values or search queries live here.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_BYTES: u64 = 128 * 1024;
const ATTRIBUTES: &[&str] = &[
    "host",
    "scope",
    "user",
    "service",
    "responsibility",
    "namespace",
    "name",
    "explanation",
    "facing",
    "type",
    "status",
];
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSnapshot {
    pub revision: u64,
    pub profiles: BTreeMap<String, ViewProfile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewProfile {
    pub tree_order: Vec<String>,
    #[serde(default)]
    pub facets: BTreeMap<String, ProfileFacet>,
    pub view_filter: ProfileViewFilter,
    pub human_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileFacet {
    pub mode: ProfileFacetMode,
    #[serde(default)]
    pub selected: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileFacetMode {
    All,
    Whitelist,
    Blacklist,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileViewFilter {
    Required,
    All,
    Keys,
    Passwords,
    PublicInfo,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    #[serde(default)]
    profiles: BTreeMap<String, ViewProfile>,
}

pub struct ProfileStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl ProfileStore {
    pub fn new(repository: &Path) -> io::Result<Self> {
        let path = repository.join("nix-secrets-profiles.toml");
        reject_symlink(&path)?;
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }

    pub fn list(&self) -> io::Result<ProfileSnapshot> {
        let _lock = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("profile lock poisoned"))?;
        self.read()
    }

    pub fn save(
        &self,
        name: &str,
        profile: ViewProfile,
        expected: u64,
    ) -> io::Result<ProfileSnapshot> {
        validate_name(name)?;
        profile.validate()?;
        self.change(expected, |document| {
            document.profiles.insert(name.into(), profile);
            Ok(())
        })
    }

    pub fn delete(&self, name: &str, expected: u64) -> io::Result<ProfileSnapshot> {
        validate_name(name)?;
        self.change(expected, |document| {
            if document.profiles.remove(name).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "profile does not exist",
                ));
            }
            Ok(())
        })
    }

    fn change(
        &self,
        expected: u64,
        edit: impl FnOnce(&mut Document) -> io::Result<()>,
    ) -> io::Result<ProfileSnapshot> {
        let _lock = self
            .lock
            .lock()
            .map_err(|_| io::Error::other("profile lock poisoned"))?;
        let current = self.read()?;
        if current.revision != expected {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "profiles changed; reload before saving",
            ));
        }
        let mut document = Document {
            version: 1,
            profiles: current.profiles,
        };
        edit(&mut document)?;
        let content = toml::to_string_pretty(&document).map_err(io::Error::other)?;
        if content.len() as u64 > MAX_BYTES {
            return Err(invalid("profile file is too large"));
        }
        atomic_write(&self.path, content.as_bytes())?;
        self.read()
    }

    fn read(&self) -> io::Result<ProfileSnapshot> {
        reject_symlink(&self.path)?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ProfileSnapshot::default());
            }
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_BYTES {
            return Err(invalid(
                "profile path is not a regular file of acceptable size",
            ));
        }
        let mut content = String::new();
        file.take(MAX_BYTES + 1).read_to_string(&mut content)?;
        if content.len() as u64 > MAX_BYTES {
            return Err(invalid("profile file is too large"));
        }
        let document: Document =
            toml::from_str(&content).map_err(|error| invalid(error.to_string()))?;
        if document.version != 1 {
            return Err(invalid("unsupported profile file version"));
        }
        if document.profiles.len() > 64 {
            return Err(invalid("too many profiles"));
        }
        for (name, profile) in &document.profiles {
            validate_name(name)?;
            profile.validate()?;
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        content.hash(&mut hasher);
        Ok(ProfileSnapshot {
            revision: hasher.finish(),
            profiles: document.profiles,
        })
    }
}

#[cfg(test)]
mod tests;

impl ViewProfile {
    pub fn validate(&self) -> io::Result<()> {
        if self.tree_order.len() > ATTRIBUTES.len()
            || self.tree_order.iter().collect::<BTreeSet<_>>().len() != self.tree_order.len()
            || self
                .tree_order
                .iter()
                .any(|name| !ATTRIBUTES.contains(&name.as_str()))
        {
            return Err(invalid("invalid or duplicate tree attribute"));
        }
        if self.facets.len() > ATTRIBUTES.len() {
            return Err(invalid("too many facet filters"));
        }
        for (attribute, facet) in &self.facets {
            if !ATTRIBUTES.contains(&attribute.as_str())
                || facet.selected.len() > 1024
                || facet
                    .selected
                    .iter()
                    .any(|value| value.len() > 256 || value.chars().any(char::is_control))
                || facet.mode == ProfileFacetMode::All && !facet.selected.is_empty()
            {
                return Err(invalid("invalid facet filter"));
            }
        }
        Ok(())
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " _-.".contains(c))
    {
        return Err(invalid(
            "profile name must be 1–64 letters, numbers, spaces, _, - or .",
        ));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(invalid(
            "profile path must be a regular file, not a symlink",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn atomic_write(path: &Path, content: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("profile path has no parent"))?;
    reject_symlink(path)?;
    let temp = parent.join(format!(
        ".nix-secrets-profiles-{}-{}.tmp",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        reject_symlink(path)?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
