//! One deployment across the secret root and the public-info root.
//!
//! Both roots get generation `id` and a pending pointer `.current-<id>`
//! before either switches. The secret root switches first; its `.current`
//! naming `id` is the commit point. Recovery then finishes the public-info
//! root: its pending `.current-<id>` becomes `.current` if the secret root's
//! `.current` names `id`, and is discarded otherwise. A pending pointer in
//! the secret root was never committed and is discarded.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Root {
    Secrets,
    Public,
}

/// Publishes `secrets_batch` and `public_batch` as one deployment. A failure
/// or crash leaves both roots at their previous generation, or (after
/// recovery) both at the new one. Returns the versions installed before.
pub fn deploy_together(
    secrets: &Deployer,
    public: &Deployer,
    secrets_batch: Option<&ResolvedBatch>,
    public_batch: Option<&ResolvedBatch>,
) -> Result<BTreeMap<String, String>, DeployError> {
    together(secrets, public, secrets_batch, public_batch, None)
}

/// Finishes or discards an interrupted deployment in both roots. Absent roots
/// are left alone.
pub fn recover(secrets: &Deployer, public: &Deployer) -> Result<(), DeployError> {
    check_pair(secrets, public)?;
    let secrets_lock = secrets.lock_existing()?;
    let public_lock = public.lock_existing()?;
    if secrets_lock.is_some() {
        secrets.recover_locked()?;
    }
    if public_lock.is_some() {
        public.recover_locked()?;
    }
    Ok(())
}

pub(super) fn together(
    secrets: &Deployer,
    public: &Deployer,
    secrets_batch: Option<&ResolvedBatch>,
    public_batch: Option<&ResolvedBatch>,
    fail: Option<(Root, FailurePoint)>,
) -> Result<BTreeMap<String, String>, DeployError> {
    check_pair(secrets, public)?;
    let secrets_entries = validated(secrets_batch, secrets)?;
    let public_entries = validated(public_batch, public)?;
    if secrets_entries.is_none() && public_entries.is_none() {
        return Err(DeployError::Invalid("deployment is empty".into()));
    }
    let at = |root| fail.and_then(|(failing, point)| (failing == root).then_some(point));
    let (secrets_fail, public_fail) = (at(Root::Secrets), at(Root::Public));
    let in_secrets = |error: DeployError| error.during(&secrets.publishing());
    let in_public = |error: DeployError| error.during(&public.publishing());

    // Lock order: secret root, then public-info root.
    secrets.prepare_root().map_err(in_secrets)?;
    public.prepare_root().map_err(in_public)?;
    let _secrets_lock = secrets.lock_deployments().map_err(in_secrets)?;
    let _public_lock = public.lock_deployments().map_err(in_public)?;
    secrets.recover_locked()?;
    public.recover_locked()?;

    let id = generation_id();
    let mut previous = BTreeMap::new();
    let mut publish = || -> Result<(), DeployError> {
        if let Some(entries) = &public_entries {
            previous.extend(
                public
                    .prepare(entries, &id, public_fail)
                    .map_err(in_public)?,
            );
        }
        if let Some(entries) = &secrets_entries {
            previous.extend(
                secrets
                    .prepare(entries, &id, secrets_fail)
                    .map_err(in_secrets)?,
            );
            // The commit point.
            secrets.switch(&id, secrets_fail).map_err(in_secrets)?;
        }
        if public_entries.is_some() {
            public.switch(&id, public_fail).map_err(in_public)?;
        }
        if secrets_entries.is_some() {
            secrets.prune(&id, secrets_fail).map_err(in_secrets)?;
        }
        if public_entries.is_some() {
            public.prune(&id, public_fail).map_err(in_public)?;
        }
        Ok(())
    };
    let result = publish();
    // An injected failure stands for a crash, which cleans up nothing.
    if result.is_err() && fail.is_none() {
        let _ = secrets.recover_locked();
        let _ = public.recover_locked();
    }
    result.map(|()| previous)
}

fn validated<'a>(
    batch: Option<&'a ResolvedBatch>,
    deployer: &Deployer,
) -> Result<Option<Vec<ValidatedSecret<'a>>>, DeployError> {
    batch
        .filter(|batch| !batch.entries.is_empty())
        .map(validate)
        .transpose()
        .map_err(|error| error.during(&deployer.publishing()))
}

fn check_pair(secrets: &Deployer, public: &Deployer) -> Result<(), DeployError> {
    if secrets.commit_root.is_none() && public.commit_root.as_ref() == Some(&secrets.root) {
        Ok(())
    } else {
        Err(DeployError::Invalid(
            "public-info root is not paired with this secret root".into(),
        ))
    }
}

impl Deployer {
    /// Recovers this root alone, under its lock. A public-info root reads the
    /// secret root's `.current` without locking it: every deployment that
    /// moves that pointer holds this root's lock too.
    pub(crate) fn recover_alone(&self) -> Result<(), DeployError> {
        match self.lock_existing()? {
            Some(_lock) => self.recover_locked(),
            None => Ok(()),
        }
    }

    pub(super) fn recover_locked(&self) -> Result<(), DeployError> {
        self.recover_pending()
            .map_err(|error| error.during(&format!("recovering {}", self.root.display())))
    }

    fn recover_pending(&self) -> Result<(), DeployError> {
        let committed = match &self.commit_root {
            Some(root) => current_generation(root)?,
            None => None,
        };
        let current = current_generation(&self.root)?;
        let store = self.root.join(".generations");
        let mut forward = None;
        let mut discarded = false;
        for id in self.pending_pointers()? {
            if committed.as_deref() == Some(id.as_str()) {
                forward = Some(id);
                continue;
            }
            fs::remove_file(self.pending(&id))?;
            discarded = true;
            if current.as_deref() == Some(id.as_str()) {
                continue;
            }
            let generation = store.join(&id);
            match fs::symlink_metadata(&generation) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    fs::remove_dir_all(&generation)?
                }
                Ok(_) => {
                    return Err(DeployError::Invalid(
                        "uncommitted generation is not a real directory".into(),
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if discarded {
            if store.exists() {
                sync_directory(&store)?;
            }
            sync_directory(&self.root)?;
        }
        if let Some(id) = forward {
            require_real_directory(&store.join(&id), "committed generation")?;
            fs::rename(self.pending(&id), self.root.join(".current"))?;
            sync_directory(&self.root)?;
        }
        Ok(())
    }

    /// Generation IDs of the pending pointers `.current-<id>` in this root.
    fn pending_pointers(&self) -> Result<Vec<String>, DeployError> {
        let mut ids = Vec::new();
        for item in fs::read_dir(&self.root)? {
            let item = item?;
            let name = item.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|name| name.strip_prefix(".current-"))
            else {
                continue;
            };
            if !valid_generation(id.as_ref())
                || !fs::symlink_metadata(item.path())?.file_type().is_symlink()
                || fs::read_link(item.path())? != Path::new(".generations").join(id)
            {
                return Err(DeployError::Invalid(format!(
                    "unexpected pending pointer {}",
                    item.path().display()
                )));
            }
            ids.push(id.to_owned());
        }
        Ok(ids)
    }

    fn lock_existing(&self) -> Result<Option<Flock<File>>, DeployError> {
        match fs::symlink_metadata(&self.root) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        require_real_directory(&self.root, "secret root")?;
        self.require_root_metadata(&fs::metadata(&self.root)?, "secret root")?;
        self.lock_deployments().map(Some)
    }
}

/// The generation `root/.current` names, if any.
fn current_generation(root: &Path) -> Result<Option<String>, DeployError> {
    let target = match fs::read_link(root.join(".current")) {
        Ok(target) => target,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_current_target(&target)?;
    Ok(target
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned))
}

#[cfg(test)]
pub(super) fn together_failing_at(
    secrets: &Deployer,
    public: &Deployer,
    secrets_batch: &ResolvedBatch,
    public_batch: &ResolvedBatch,
    root: Root,
    point: FailurePoint,
) -> Result<(), DeployError> {
    together(
        secrets,
        public,
        Some(secrets_batch),
        Some(public_batch),
        Some((root, point)),
    )
    .map(|_| ())
}
