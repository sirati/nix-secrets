use super::*;

impl SecretStore {
    pub(super) fn with_lock<T>(
        &self,
        write: bool,
        action: impl FnOnce(&mut StoreDocument) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&self.lock_path)?;
        flock(
            &lock,
            if write {
                FlockOperation::LockExclusive
            } else {
                FlockOperation::LockShared
            },
        )
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
        let mut document = self.read_document()?;
        let result = action(&mut document)?;
        if write {
            self.write_document(parent, &document)?;
        }
        Ok(result)
    }

    fn read_document(&self) -> Result<StoreDocument, StoreError> {
        match fs::read_to_string(&self.path) {
            Ok(value) => Ok(toml::from_str(&value)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(StoreDocument::default()),
            Err(error) => Err(error.into()),
        }
    }

    fn write_document(&self, parent: &Path, document: &StoreDocument) -> Result<(), StoreError> {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let name = format!(".nix-secrets.{}.{}.tmp", std::process::id(), id);
        let temp_path = parent.join(name);
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        let result = (|| {
            temp.write_all(toml::to_string_pretty(document)?.as_bytes())?;
            temp.sync_all()?;
            fs::rename(&temp_path, &self.path)?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
            File::open(parent)?.sync_all()?;
            Ok::<_, StoreError>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp_path);
        }
        result
    }
}
