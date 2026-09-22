use crate::manifest::load_schema;
use crate::{DeployError, SecretDeployment};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nix::unistd::{Group, User};
use nix_secrets_core::{GeneratedSecretType, SecretPath};
use nix_secrets_storagebox_bootstrap::{
    ClientContribution, DevUrandom, Engine, OsKeyGenerator, Output, RusshBackend, StorageBoxTask,
    SystemClock,
};
use nix_secrets_transport::TaskEntry;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroizing;

const MAX_PASSWORD_BYTES: usize = 64 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;

pub fn run_generated_tasks(
    manifest: &Path,
    hostname: &str,
    entries: &[TaskEntry],
) -> Result<Vec<SecretDeployment>, DeployError> {
    let schema = load_schema(manifest)?;
    let mut outputs = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = SecretPath::parse(&entry.identifier)
            .map_err(|error| invalid(format!("invalid task identifier: {error}")))?;
        if path.components().first().map(String::as_str) != Some(hostname) {
            return Err(invalid("generated task belongs to another host"));
        }
        let spec = schema
            .generated_secret(&path)
            .map_err(|error| invalid(format!("generated task is absent from manifest: {error}")))?;
        match &spec.generated_secret.secret_type {
            GeneratedSecretType::StorageBoxSshKey => {}
        }
        let generated = spec.generated_secret;
        validate_output(&path, &generated.output)?;
        let mode = parse_mode(&generated.output.mode)?;
        let task = StorageBoxTask {
            schema_version: 1,
            task_id: entry.identifier.clone(),
            target_hostname: hostname.into(),
            storage_box_host: generated.bootstrap.host,
            storage_box_user: generated.bootstrap.user,
            port: generated.bootstrap.port,
            pinned_host_keys: generated.bootstrap.host_public_keys,
            output: Output {
                path: generated.output.path.clone(),
                owner: generated.output.owner,
                group: generated.output.group,
                mode,
            },
        };
        let password = decode_password(&entry.password_base64)?;
        let contribution = decode_contribution(&entry.client_contribution_base64)?;
        let existing = read_existing_key(Path::new(&task.output.path))?;
        let mut engine = Engine {
            backend: RusshBackend,
            entropy: DevUrandom::open().map_err(task_error)?,
            generator: OsKeyGenerator,
            clock: SystemClock,
        };
        let key = engine
            .run(
                &task,
                password,
                contribution,
                existing.as_ref().map(|value| value.as_str()),
            )
            .map_err(task_error)?;
        outputs.push(SecretDeployment {
            identifier: entry.identifier.clone(),
            version_id: entry.version_id.clone(),
            contents_base64: STANDARD.encode(key.private_pem.as_bytes()),
        });
    }
    Ok(outputs)
}

fn decode_password(value: &str) -> Result<Zeroizing<Vec<u8>>, DeployError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| invalid("task password is not valid base64"))?,
    );
    if decoded.is_empty() || decoded.len() > MAX_PASSWORD_BYTES {
        return Err(invalid("task password has invalid length"));
    }
    Ok(decoded)
}

fn decode_contribution(value: &str) -> Result<ClientContribution, DeployError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| invalid("client contribution is not valid base64"))?,
    );
    let bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| invalid("client contribution must be exactly 32 bytes"))?;
    Ok(ClientContribution::new(bytes))
}

fn read_existing_key(path: &Path) -> Result<Option<Zeroizing<String>>, DeployError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(invalid(
            "existing generated key is not a bounded regular file",
        ));
    }
    let mut value = Zeroizing::new(String::with_capacity(metadata.len() as usize));
    file.read_to_string(&mut value)?;
    Ok(Some(value))
}

fn parse_mode(value: &str) -> Result<u32, DeployError> {
    let value = value.strip_prefix("0o").unwrap_or(value);
    let mode = u32::from_str_radix(value, 8).map_err(|_| invalid("invalid output mode"))?;
    if matches!(mode, 0o400 | 0o440) {
        Ok(mode)
    } else {
        Err(invalid("generated output mode must be 0400 or 0440"))
    }
}

fn validate_output(
    identifier: &SecretPath,
    output: &nix_secrets_core::Destination,
) -> Result<(), DeployError> {
    let service = identifier
        .components()
        .get(2)
        .ok_or_else(|| invalid("task identifier has no service"))?;
    let expected = Path::new("/persistent/secrets")
        .join(service)
        .join(&output.category);
    let path = Path::new(&output.path);
    if path.parent() != Some(expected.as_path()) || output.category != "backup" {
        return Err(invalid(
            "generated task output escapes its backup service boundary",
        ));
    }
    User::from_name(&output.owner)
        .map_err(|_| invalid("cannot resolve generated output owner"))?
        .ok_or_else(|| invalid("generated output owner does not exist"))?;
    Group::from_name(&output.group)
        .map_err(|_| invalid("cannot resolve generated output group"))?
        .ok_or_else(|| invalid("generated output group does not exist"))?;
    parse_mode(&output.mode)?;
    Ok(())
}

fn task_error(error: impl std::fmt::Display) -> DeployError {
    invalid(format!("storage box bootstrap failed: {error}"))
}

fn invalid(message: impl Into<String>) -> DeployError {
    DeployError::Invalid(message.into())
}
