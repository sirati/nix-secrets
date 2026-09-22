use crate::{Error, RemoteSession, SshBackend, StorageBoxTask};
use russh::client;
use russh::keys::{PublicKey, PublicKeyOrCertificate};
use russh_sftp::client::{RawSftpSession, SftpSession};
use russh_sftp::protocol::{FileAttributes, Packet, StatusCode};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

pub struct RusshBackend;

pub struct RusshSession {
    runtime: Runtime,
    sftp: SftpSession,
    raw_sftp: RawSftpSession,
    _ssh: client::Handle<PinnedHandler>,
}

#[derive(Clone)]
struct PinnedHandler {
    pins: Vec<PublicKey>,
}

impl client::Handler for PinnedHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        presented: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = presented else {
            return Ok(false);
        };
        Ok(self.pins.iter().any(|pin| pin.key_data() == key.key_data()))
    }
}

impl SshBackend for RusshBackend {
    type Session = RusshSession;

    fn connect(&mut self, task: &StorageBoxTask, password: &[u8]) -> Result<Self::Session, Error> {
        let password = Zeroizing::new(
            std::str::from_utf8(password)
                .map_err(|_| Error::Ssh("password is not UTF-8".into()))?
                .to_owned(),
        );
        let pins = task
            .pinned_host_keys
            .iter()
            .map(|pin| PublicKey::from_openssh(pin).map_err(|error| ssh_error("parse pinned host key", error)))
            .collect::<Result<Vec<_>, _>>()?;
        let runtime = Runtime::new().map_err(|error| ssh_error("create Tokio runtime", error))?;
        let address = (task.storage_box_host.clone(), task.port);
        let username = task.storage_box_user.clone();
        let (handle, sftp, raw_sftp) = runtime.block_on(async move {
            let config = Arc::new(client::Config {
                nodelay: true,
                ..Default::default()
            });
            let mut handle = client::connect(config, address, PinnedHandler { pins })
                .await
                .map_err(|error| ssh_error("connect SSH transport", error))?;
            let auth = handle
                .authenticate_password(username, password.as_str())
                .await
                .map_err(|error| ssh_error("request password authentication", error))?;
            if !auth.success() {
                return Err(Error::Ssh("password authentication rejected".into()));
            }
            let channel = handle
                .channel_open_session()
                .await
                .map_err(|error| ssh_error("open SFTP channel", error))?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .map_err(|error| ssh_error("request SFTP subsystem", error))?;
            let sftp = SftpSession::new(channel.into_stream())
                .await
                .map_err(|error| ssh_error("initialize SFTP session", error))?;
            let channel = handle
                .channel_open_session()
                .await
                .map_err(|error| ssh_error("open atomic-rename SFTP channel", error))?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .map_err(|error| ssh_error("request atomic-rename SFTP subsystem", error))?;
            let raw_sftp = RawSftpSession::new(channel.into_stream());
            raw_sftp
                .init()
                .await
                .map_err(|error| ssh_error("initialize atomic-rename SFTP session", error))?;
            Ok((handle, sftp, raw_sftp))
        })?;
        Ok(RusshSession {
            runtime,
            sftp,
            raw_sftp,
            _ssh: handle,
        })
    }
}

impl RemoteSession for RusshSession {
    fn read_authorized_keys(&mut self) -> Result<Vec<u8>, Error> {
        self.runtime.block_on(async {
            ensure_ssh_directory(&self.sftp).await?;
            if !self
                .sftp
                .try_exists(".ssh/authorized_keys")
                .await
                .map_err(|error| ssh_error("check authorized_keys existence", error))?
            {
                return Ok(Vec::new());
            }
            let value = self
                .sftp
                .read(".ssh/authorized_keys")
                .await
                .map_err(|error| ssh_error("read authorized_keys", error))?;
            if value.len() > 1024 * 1024 {
                return Err(Error::InvalidAuthorizedKeys("file exceeds 1 MiB".into()));
            }
            Ok(value)
        })
    }

    fn replace_authorized_keys_atomically(&mut self, contents: &[u8]) -> Result<(), Error> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| Error::KeyGeneration)?;
        let temporary = format!(
            ".ssh/.authorized_keys.nix-secrets-{}",
            u64::from_ne_bytes(random)
        );
        self.runtime.block_on(async {
            ensure_ssh_directory(&self.sftp).await?;
            if let Err(error) = write_staging_file(&self.sftp, &temporary, contents).await {
                if let Err(cleanup) = self.sftp.remove_file(&temporary).await {
                    return Err(Error::Ssh(format!(
                        "{error}; staging cleanup failed: {cleanup}"
                    )));
                }
                return Err(error);
            }
            let payload = rename_payload(&temporary, ".ssh/authorized_keys")?;
            let result = self
                .raw_sftp
                .extended("posix-rename@openssh.com", payload)
                .await;
            if !matches!(result, Ok(Packet::Status(ref status)) if status.status_code == StatusCode::Ok) {
                let rename = result
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "unexpected response packet".into());
                if let Err(error) = self.sftp.remove_file(&temporary).await {
                    return Err(Error::Ssh(format!(
                        "atomic authorized_keys rename failed ({rename}); staging cleanup failed: {error}"
                    )));
                }
                return Err(Error::Ssh(format!(
                    "atomic authorized_keys rename failed: {rename}"
                )));
            }
            Ok(())
        })
    }
}

async fn write_staging_file(
    sftp: &SftpSession,
    path: &str,
    contents: &[u8],
) -> Result<(), Error> {
    let mut file = sftp
        .create(path)
        .await
        .map_err(|error| ssh_error("create authorized_keys staging file", error))?;
    file.set_metadata(FileAttributes {
        permissions: Some(0o600),
        ..Default::default()
    })
    .await
    .map_err(|error| ssh_error("set authorized_keys staging permissions", error))?;
    file.write_all(contents)
        .await
        .map_err(|error| ssh_error("write authorized_keys staging file", error))?;
    file.flush()
        .await
        .map_err(|error| ssh_error("flush authorized_keys staging file", error))?;
    file.sync_all()
        .await
        .map_err(|error| ssh_error("sync authorized_keys staging file", error))?;
    file.close()
        .await
        .map_err(|error| ssh_error("close authorized_keys staging file", error))
}

async fn ensure_ssh_directory(sftp: &SftpSession) -> Result<(), Error> {
    if sftp
        .try_exists(".ssh")
        .await
        .map_err(|error| ssh_error("check .ssh existence", error))? {
        let metadata = sftp
            .symlink_metadata(".ssh")
            .await
            .map_err(|error| ssh_error("lstat .ssh", error))?;
        if !metadata.is_dir() {
            return Err(Error::Ssh(".ssh is not a real directory".into()));
        }
    } else {
        sftp
            .create_dir(".ssh")
            .await
            .map_err(|error| ssh_error("create .ssh", error))?;
    }
    sftp
        .set_metadata(
            ".ssh",
            FileAttributes {
                permissions: Some(0o700),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| ssh_error("set .ssh permissions", error))
}

fn rename_payload(old: &str, new: &str) -> Result<Vec<u8>, Error> {
    let mut value = Vec::new();
    for path in [old, new] {
        let length =
            u32::try_from(path.len()).map_err(|_| Error::Ssh("remote path too long".into()))?;
        value.extend_from_slice(&length.to_be_bytes());
        value.extend_from_slice(path.as_bytes());
    }
    Ok(value)
}

fn ssh_error(stage: &str, error: impl std::fmt::Display) -> Error {
    Error::Ssh(format!("{stage}: {error}"))
}
