use super::*;

impl Deployer {
    /// Reads version metadata from one immutable generation. An atomic pointer
    /// change during this call therefore yields either the preceding or current map.
    pub fn current_versions(&self) -> Result<BTreeMap<String, String>, DeployError> {
        let current = self.root.join(".current");
        let target = match fs::read_link(&current) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(error) => return Err(error.into()),
        };
        validate_current_target(&target)?;
        let path = self.root.join(target).join(".versions.json");
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 4 * 1024 * 1024
        {
            return Err(DeployError::Invalid(
                "generation version metadata is invalid".into(),
            ));
        }
        let input = fs::read(path)?;
        serde_json::from_slice(&input).map_err(|error| {
            DeployError::Invalid(format!("invalid generation version metadata: {error}"))
        })
    }

    pub(super) fn stage_versions(
        &self,
        staging: &Path,
        entries: &[ValidatedSecret<'_>],
    ) -> Result<(), DeployError> {
        let mut versions = self.current_versions()?;
        for entry in entries {
            versions.insert(entry.spec.identifier.clone(), entry.spec.version_id.clone());
        }
        let path = staging.join(".versions.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        serde_json::to_writer(&mut file, &versions).map_err(|error| {
            DeployError::Invalid(format!("cannot encode generation versions: {error}"))
        })?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    }

    pub(super) fn clone_current(&self, staging: &Path) -> Result<(), DeployError> {
        let target = match fs::read_link(self.root.join(".current")) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        validate_current_target(&target)?;
        clone_tree(&self.root.join(target), staging)
    }

    pub(super) fn stage_one(
        &self,
        staging: &Path,
        entry: &ValidatedSecret<'_>,
    ) -> Result<(), DeployError> {
        let path = staging.join(&entry.relative);
        create_parents(staging, path.parent().expect("validated path has parent"))?;
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(DeployError::Invalid(
                    "existing generation destination is not a regular file".into(),
                ));
            }
            fs::remove_file(&path)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&entry.spec.contents)?;
        fchown(
            file.as_raw_fd(),
            Some(Uid::from_raw(entry.spec.owner)),
            Some(Gid::from_raw(entry.spec.group)),
        )
        .map_err(|error| DeployError::Io(io::Error::from_raw_os_error(error as i32)))?;
        file.set_permissions(fs::Permissions::from_mode(entry.spec.mode))?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        if metadata.uid() != entry.spec.owner
            || metadata.gid() != entry.spec.group
            || metadata.mode() & 0o7777 != entry.spec.mode
        {
            return Err(DeployError::Invalid(
                "staged secret metadata does not match manifest".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn prune_generations(&self, active: &str) -> Result<(), DeployError> {
        let store = self.root.join(".generations");
        let mut generations = Vec::new();
        for item in fs::read_dir(&store)? {
            let item = item?;
            let name = item.file_name().to_string_lossy().into_owned();
            let metadata = fs::symlink_metadata(item.path())?;
            if name.starts_with(".staging-") {
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    fs::remove_dir_all(item.path())?;
                }
            } else if valid_generation(item.file_name().as_os_str())
                && metadata.is_dir()
                && !metadata.file_type().is_symlink()
            {
                generations.push(name);
            }
        }
        generations.sort_unstable_by(|a, b| b.cmp(a));
        let mut keep = HashSet::from([active.to_owned()]);
        for name in &generations {
            if keep.len() == RETAINED_GENERATIONS {
                break;
            }
            keep.insert(name.clone());
        }
        for name in generations {
            if !keep.contains(&name) {
                fs::remove_dir_all(store.join(name))?;
            }
        }
        sync_directory(&store)
    }

    #[cfg(test)]
    pub(super) fn deploy_failing_at(
        &self,
        batch: &ResolvedBatch,
        point: FailurePoint,
    ) -> Result<(), DeployError> {
        self.deploy_inner(batch, Some(point)).map(|_| ())
    }
}

fn create_parents(base: &Path, destination: &Path) -> Result<(), DeployError> {
    let relative = destination
        .strip_prefix(base)
        .map_err(|_| DeployError::Invalid("destination escaped generation".into()))?;
    let mut cursor = base.to_path_buf();
    for component in relative.components() {
        cursor.push(component);
        if !cursor.exists() {
            create_directory(&cursor, 0o711)?;
        }
        require_real_directory(&cursor, "secret directory")?;
    }
    Ok(())
}
