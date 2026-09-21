use crate::schema::{ResolvedBatch, ResolvedSecret};
use crate::DeployError;
use std::collections::HashSet;
use std::path::PathBuf;

pub(crate) struct ValidatedSecret<'a> {
    pub spec: &'a ResolvedSecret,
    pub relative: PathBuf,
}

pub(crate) fn validate(batch: &ResolvedBatch) -> Result<Vec<ValidatedSecret<'_>>, DeployError> {
    if batch.entries.is_empty() {
        return Err(DeployError::Invalid("deployment is empty".into()));
    }
    let mut destinations = HashSet::new();
    batch
        .entries
        .iter()
        .map(|spec| {
            validate_name("service", &spec.service)?;
            validate_name("secret", &spec.secret)?;
            validate_mode(spec.mode)?;
            if spec.identifier.is_empty() || spec.version_id.is_empty() {
                return Err(DeployError::Invalid(
                    "secret identifier and version must not be empty".into(),
                ));
            }
            let relative = PathBuf::from(&spec.service)
                .join(spec.class.directory())
                .join(&spec.secret);
            if !destinations.insert(relative.clone()) {
                return Err(DeployError::Invalid(format!(
                    "duplicate destination: {}",
                    relative.display()
                )));
            }
            Ok(ValidatedSecret { spec, relative })
        })
        .collect()
}

pub(crate) fn validate_name(kind: &str, value: &str) -> Result<(), DeployError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && value != "."
        && value != "..";
    if valid {
        Ok(())
    } else {
        Err(DeployError::Invalid(format!("invalid {kind} name")))
    }
}

pub(crate) fn validate_mode(mode: u32) -> Result<(), DeployError> {
    if mode & !0o440 != 0 || mode & 0o400 == 0 {
        Err(DeployError::Invalid(
            "mode must grant owner read access and no write, execute, or other access".into(),
        ))
    } else {
        Ok(())
    }
}
