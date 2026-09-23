use super::*;

impl SecretPath {
    pub fn new(parts: impl IntoIterator<Item = String>) -> Result<Self, SchemaError> {
        let parts: Vec<_> = parts.into_iter().collect();
        if parts.len() < 4 {
            return Err(SchemaError::TooShort);
        }
        for part in &parts {
            validate_component(part)?;
        }
        validate_namespace(&parts[1])?;
        Ok(Self(parts))
    }

    pub fn parse(path: &str) -> Result<Self, SchemaError> {
        Self::new(path.split('.').map(str::to_owned))
    }

    pub fn components(&self) -> &[String] {
        &self.0
    }
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.join("."))
    }
}
