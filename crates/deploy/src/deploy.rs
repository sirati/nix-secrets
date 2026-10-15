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

mod recovery;
mod staging;

pub use recovery::{deploy_together, recover};

const RETAINED_GENERATIONS: usize = 3;

#[derive(Debug)]
pub enum DeployError {
    Invalid(String),
    Io(io::Error),
    /// An I/O failure with the step and path it happened in.
    Context(String, io::Error),
    /// A prerequisite of one value is absent on this host, such as a
    /// known_hosts file that is not installed yet. That value is left out
    /// and reported; the rest of the batch deploys.
    Missing(String),
}

impl DeployError {
    /// `reading /path for task X: No such file or directory`.
    pub fn context(step: &str, error: io::Error) -> Self {
        Self::Context(step.to_owned(), error)
    }

    /// Adds the step to an error that does not name one yet.
    pub fn during(self, step: &str) -> Self {
        match self {
            Self::Io(error) => Self::Context(step.to_owned(), error),
            Self::Context(inner, error) => Self::Context(format!("{step}: {inner}"), error),
            Self::Invalid(message) => Self::Invalid(format!("{step}: {message}")),
            missing @ Self::Missing(_) => missing,
        }
    }
}

impl fmt::Display for DeployError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Io(error) => error.fmt(formatter),
            Self::Context(step, error) => write!(formatter, "{step}: {error}"),
            Self::Missing(message) => write!(formatter, "not deployed: {message}"),
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
    /// The root whose `.current` commits a joint deployment into this one.
    commit_root: Option<PathBuf>,
}

impl Deployer {
    pub fn persistent() -> Self {
        Self {
            root: PathBuf::from("/persistent/secrets"),
            require_root_owner: true,
            commit_root: None,
        }
    }

    /// Joint deployments into this root commit through the secret root.
    pub fn public_info() -> Self {
        Self {
            root: PathBuf::from("/persistent/public-info"),
            require_root_owner: true,
            commit_root: Some(PathBuf::from("/persistent/secrets")),
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
            commit_root: None,
        })
    }

    /// Makes this the public-info root of `secrets` for [`deploy_together`].
    pub fn committed_with(mut self, secrets: &Deployer) -> Self {
        self.commit_root = Some(secrets.root.clone());
        self
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

    /// Deploys into this root alone, after finishing or discarding an
    /// interrupted deployment. The receiver's two roots go through
    /// [`deploy_together`] instead.
    pub fn deploy(&self, batch: &ResolvedBatch) -> Result<(), DeployError> {
        self.deploy_inner(batch, None, |_| Ok(true)).map(|_| ())
    }

    /// Like [`Deployer::deploy`], but only when `proceed` approves the root
    /// as it is under the deployment lock, after recovery: a concurrent
    /// deployment has either finished before `proceed` looks or waits until
    /// this one is done. Returns whether `batch` was deployed.
    pub fn deploy_if(
        &self,
        batch: &ResolvedBatch,
        proceed: impl FnOnce(&Self) -> Result<bool, DeployError>,
    ) -> Result<bool, DeployError> {
        self.deploy_inner(batch, None, proceed)
    }

    fn deploy_inner(
        &self,
        batch: &ResolvedBatch,
        fail: Option<FailurePoint>,
        proceed: impl FnOnce(&Self) -> Result<bool, DeployError>,
    ) -> Result<bool, DeployError> {
        let entries = validate(batch)?;
        self.prepare_root()?;
        let _lock = self.lock_deployments()?;
        self.recover_locked()?;
        if !proceed(self)? {
            return Ok(false);
        }
        let id = generation_id();
        let result = self
            .prepare(&entries, &id, fail)
            .and_then(|_| self.switch(&id, fail))
            .and_then(|()| self.prune(&id, fail));
        // An injected failure stands for a crash, which cleans up nothing.
        if result.is_err() && fail.is_none() {
            let _ = self.recover_locked();
        }
        result
            .map(|()| true)
            .map_err(|error| error.during(&self.publishing()))
    }

    /// Publishes generation `id` up to its pending pointer `.current-<id>`.
    /// Returns the versions installed before it.
    fn prepare(
        &self,
        entries: &[ValidatedSecret<'_>],
        id: &str,
        fail: Option<FailurePoint>,
    ) -> Result<BTreeMap<String, String>, DeployError> {
        self.prepare_store()?;
        let previous = self.current_versions()?;
        fail_at(fail, FailurePoint::StorePrepared)?;
        let store = self.root.join(".generations");
        let staging = store.join(format!(".staging-{id}"));
        create_directory(&staging, 0o700)?;
        self.clone_current(&staging)?;
        fail_at(fail, FailurePoint::BaseCopied)?;
        for (index, entry) in entries.iter().enumerate() {
            self.stage_one(&staging, entry)
                .map_err(|error| error.during(&format!("staging {}", entry.spec.identifier)))?;
            fail_at(fail, FailurePoint::SecretStaged(index))?;
        }
        self.stage_versions(&staging, entries)?;
        fail_at(fail, FailurePoint::VersionsStaged)?;
        sync_tree(&staging)?;
        fail_at(fail, FailurePoint::GenerationSynced)?;

        let generation = store.join(id);
        fs::rename(&staging, &generation)?;
        sync_directory(&store)?;
        fail_at(fail, FailurePoint::GenerationPublished)?;

        self.prepare_service_links(entries)?;
        sync_directory(&self.root)?;
        fail_at(fail, FailurePoint::ServiceLinksPrepared)?;

        std::os::unix::fs::symlink(Path::new(".generations").join(id), self.pending(id))?;
        sync_directory(&self.root)?;
        fail_at(fail, FailurePoint::PointerPrepared)?;
        fs::set_permissions(&generation, fs::Permissions::from_mode(0o711))?;
        sync_directory(&generation)?;
        fail_at(fail, FailurePoint::GenerationAccessible)?;
        Ok(previous)
    }

    /// Makes the prepared generation `id` current.
    fn switch(&self, id: &str, fail: Option<FailurePoint>) -> Result<(), DeployError> {
        fs::rename(self.pending(id), self.root.join(".current"))?;
        fail_at(fail, FailurePoint::PointerSwitched)?;
        sync_directory(&self.root)?;
        fail_at(fail, FailurePoint::PointerSynced)
    }

    fn prune(&self, id: &str, fail: Option<FailurePoint>) -> Result<(), DeployError> {
        self.prune_generations(id)?;
        fail_at(fail, FailurePoint::Pruned)
    }

    fn pending(&self, id: &str) -> PathBuf {
        self.root.join(format!(".current-{id}"))
    }

    fn publishing(&self) -> String {
        format!("publishing a generation under {}", self.root.display())
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
    Pruned,
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
