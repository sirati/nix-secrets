use crate::fsutil::{
    clone_tree, create_directory, generation_id, require_real_directory, sync_directory, sync_tree,
    valid_generation,
};
use crate::validate::{validate, validate_name, ValidatedSecret};
use crate::{ResolvedBatch, SecretClass};
use nix::fcntl::{Flock, FlockArg};
use nix::unistd::{fchown, Gid, Uid};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

mod staging;

const RETAINED_GENERATIONS: usize = 3;

#[derive(Debug)]
pub enum DeployError {
    Invalid(String),
    Io(io::Error),
}

impl fmt::Display for DeployError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for DeployError {}
impl From<io::Error> for DeployError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct Deployer {
    root: PathBuf,
    require_root_owner: bool,
}

impl Deployer {
    pub fn persistent() -> Self {
        Self {
            root: PathBuf::from("/persistent/secrets"),
            require_root_owner: true,
        }
    }

    pub fn at(root: impl Into<PathBuf>) -> Result<Self, DeployError> {
        let root = root.into();
        if !root.is_absolute() {
            return Err(DeployError::Invalid("secret root must be absolute".into()));
        }
        Ok(Self {
            root,
            require_root_owner: false,
        })
    }

    /// Stable consumer path. Consumers must not retain its resolved generation
    /// path across deployments.
    pub fn secret_path(
        &self,
        service: &str,
        class: SecretClass,
        secret: &str,
    ) -> Result<PathBuf, DeployError> {
        validate_name("service", service)?;
        validate_name("secret", secret)?;
        Ok(self.root.join(service).join(class.directory()).join(secret))
    }

    pub fn deploy(&self, batch: &ResolvedBatch) -> Result<(), DeployError> {
        self.deploy_inner(batch, None)
    }

    fn deploy_inner(
        &self,
        batch: &ResolvedBatch,
        fail: Option<FailurePoint>,
    ) -> Result<(), DeployError> {
        let entries = validate(batch)?;
        self.prepare_root()?;
        let _lock = self.lock_deployments()?;
        self.prepare_store()?;
        fail_at(fail, FailurePoint::StorePrepared)?;
        let id = generation_id();
        let store = self.root.join(".generations");
        let staging = store.join(format!(".staging-{id}"));
        create_directory(&staging, 0o700)?;
        self.clone_current(&staging)?;
        fail_at(fail, FailurePoint::BaseCopied)?;
        for (index, entry) in entries.iter().enumerate() {
            self.stage_one(&staging, entry)?;
            fail_at(fail, FailurePoint::SecretStaged(index))?;
        }
        self.stage_versions(&staging, &entries)?;
        fail_at(fail, FailurePoint::VersionsStaged)?;
        sync_tree(&staging)?;
        fail_at(fail, FailurePoint::GenerationSynced)?;

        let generation = store.join(&id);
        fs::rename(&staging, &generation)?;
        sync_directory(&store)?;
        fail_at(fail, FailurePoint::GenerationPublished)?;

        self.prepare_service_links(&entries)?;
        sync_directory(&self.root)?;
        fail_at(fail, FailurePoint::ServiceLinksPrepared)?;

        let pending = self.root.join(format!(".current-{id}"));
        std::os::unix::fs::symlink(Path::new(".generations").join(&id), &pending)?;
        sync_directory(&self.root)?;
        fail_at(fail, FailurePoint::PointerPrepared)?;
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o711))?;
        sync_directory(&generation)?;
        fail_at(fail, FailurePoint::GenerationAccessible)?;
        fs::rename(&pending, self.root.join(".current"))?;
        fail_at(fail, FailurePoint::PointerSwitched)?;
        sync_directory(&self.root)?;
        fail_at(fail, FailurePoint::PointerSynced)?;
        self.prune_generations(&id)?;
        Ok(())
    }

    fn prepare_root(&self) -> Result<(), DeployError> {
        if !self.root.exists() {
            match create_directory(&self.root, 0o711) {
                Err(DeployError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {}
                result => result?,
            }
        }
        require_real_directory(&self.root, "secret root")?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o711))?;
        self.require_root_metadata(&fs::metadata(&self.root)?, "secret root")?;
        Ok(())
    }

    fn lock_deployments(&self) -> Result<Flock<File>, DeployError> {
        let path = self.root.join(".deploy-lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(DeployError::Invalid(
                "deployment lock is not a regular file".into(),
            ));
        }
        self.require_root_metadata(&metadata, "deployment lock")?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_, error)| DeployError::Io(io::Error::from_raw_os_error(error as i32)))
    }

    fn prepare_store(&self) -> Result<(), DeployError> {
        let store = self.root.join(".generations");
        if !store.exists() {
            create_directory(&store, 0o711)?;
        }
        require_real_directory(&store, "generation store")?;
        fs::set_permissions(&store, fs::Permissions::from_mode(0o711))?;
        self.require_root_metadata(&fs::metadata(&store)?, "generation store")?;
        if fs::metadata(&self.root)?.dev() != fs::metadata(&store)?.dev() {
            return Err(DeployError::Invalid(
                "generation store must share the secret root filesystem".into(),
            ));
        }
        self.validate_current()
    }

    fn require_root_metadata(
        &self,
        metadata: &fs::Metadata,
        label: &str,
    ) -> Result<(), DeployError> {
        if self.require_root_owner && (metadata.uid() != 0 || metadata.gid() != 0) {
            Err(DeployError::Invalid(format!(
                "{label} must be owned by root"
            )))
        } else {
            Ok(())
        }
    }

    fn prepare_service_links(&self, entries: &[ValidatedSecret<'_>]) -> Result<(), DeployError> {
        let services: HashSet<_> = entries
            .iter()
            .map(|entry| entry.spec.service.as_str())
            .collect();
        for service in services {
            let link = self.root.join(service);
            let expected = Path::new(".current").join(service);
            match fs::symlink_metadata(&link) {
                Ok(metadata)
                    if metadata.file_type().is_symlink() && fs::read_link(&link)? == expected => {}
                Ok(_) => {
                    return Err(DeployError::Invalid(format!(
                        "public service path is not the expected link: {service}"
                    )))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std::os::unix::fs::symlink(expected, link)?
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn validate_current(&self) -> Result<(), DeployError> {
        let current = self.root.join(".current");
        let metadata = match fs::symlink_metadata(&current) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_symlink() {
            return Err(DeployError::Invalid(
                "current pointer is not a symbolic link".into(),
            ));
        }
        let target = fs::read_link(&current)?;
        validate_current_target(&target)?;
        require_real_directory(&self.root.join(target), "current generation")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePoint {
    StorePrepared,
    BaseCopied,
    SecretStaged(usize),
    VersionsStaged,
    GenerationSynced,
    GenerationPublished,
    ServiceLinksPrepared,
    PointerPrepared,
    GenerationAccessible,
    PointerSwitched,
    PointerSynced,
}

fn fail_at(requested: Option<FailurePoint>, actual: FailurePoint) -> Result<(), DeployError> {
    if requested == Some(actual) {
        Err(DeployError::Invalid("injected crash".into()))
    } else {
        Ok(())
    }
}

fn validate_current_target(target: &Path) -> Result<(), DeployError> {
    let parts: Vec<_> = target.components().collect();
    if parts.len() == 2
        && parts[0].as_os_str() == ".generations"
        && valid_generation(parts[1].as_os_str())
    {
        Ok(())
    } else {
        Err(DeployError::Invalid(
            "current pointer has an invalid target".into(),
        ))
    }
}

#[cfg(test)]
mod tests;
