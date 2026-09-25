use super::*;

impl BackendClient {
    pub fn list_public_info(&mut self) -> io::Result<BTreeMap<String, PublicInfoRecord>> {
        match self.exchange(&Request::ListPublicInfo)? {
            Response::PublicInfoEntries { entries } => Ok(entries),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn get_public_info(&mut self, shared_id: &str) -> io::Result<Option<PublicInfoRecord>> {
        match self.exchange(&Request::GetPublicInfo {
            shared_id: shared_id.into(),
        })? {
            Response::PublicInfo { value } => Ok(value),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn set_public_info_if_version(
        &mut self,
        path: &SecretPath,
        value: PublicInfoRecord,
        expected_version: Option<String>,
    ) -> io::Result<()> {
        match self.exchange(&Request::SetPublicInfoIfVersion {
            path: path.clone(),
            value,
            expected_version,
        })? {
            Response::Updated => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn remove_public_info_if_version(
        &mut self,
        path: &SecretPath,
        expected_version: String,
    ) -> io::Result<bool> {
        match self.exchange(&Request::RemovePublicInfoIfVersion {
            path: path.clone(),
            expected_version,
        })? {
            Response::Removed { existed } => Ok(existed),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }
}
