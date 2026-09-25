use super::*;

impl BackendClient {
    pub fn list_profiles(&mut self) -> io::Result<ProfileSnapshot> {
        match self.exchange(&Request::ListProfiles)? {
            Response::Profiles { snapshot } => Ok(snapshot),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn save_profile(
        &mut self,
        name: String,
        profile: ViewProfile,
        expected_revision: u64,
    ) -> io::Result<ProfileSnapshot> {
        match self.exchange(&Request::SaveProfile {
            name,
            profile,
            expected_revision,
        })? {
            Response::Profiles { snapshot } => Ok(snapshot),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn delete_profile(
        &mut self,
        name: String,
        expected_revision: u64,
    ) -> io::Result<ProfileSnapshot> {
        match self.exchange(&Request::DeleteProfile {
            name,
            expected_revision,
        })? {
            Response::Profiles { snapshot } => Ok(snapshot),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }
}
