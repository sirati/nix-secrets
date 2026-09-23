use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueType {
    Password,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConsumerConstraints {
    pub cannot_handle_shorter_than: Option<usize>,
    pub cannot_handle_longer_than: Option<usize>,
    pub matching_regex: Option<String>,
}

impl ConsumerConstraints {
    pub fn validate_definition(&self) -> Result<(), String> {
        if self.cannot_handle_shorter_than.unwrap_or(0)
            > self.cannot_handle_longer_than.unwrap_or(usize::MAX)
        {
            return Err("minimum consumer length exceeds maximum".into());
        }
        if let Some(pattern) = &self.matching_regex {
            if pattern.is_empty() || pattern.len() > 4096 {
                return Err("consumer matching regex must contain 1 through 4096 bytes".into());
            }
            Regex::new(&format!(r"\A(?:{pattern})\z"))
                .map_err(|error| format!("invalid consumer matching regex: {error}"))?;
        }
        Ok(())
    }

    pub fn accepts(&self, value: &str) -> Result<(), String> {
        let length = value.chars().count();
        if length < self.cannot_handle_shorter_than.unwrap_or(0) {
            return Err("password is shorter than the consumer accepts".into());
        }
        if length > self.cannot_handle_longer_than.unwrap_or(usize::MAX) {
            return Err("password is longer than the consumer accepts".into());
        }
        if let Some(pattern) = &self.matching_regex {
            let regex = Regex::new(&format!(r"\A(?:{pattern})\z"))
                .map_err(|error| format!("invalid consumer matching regex: {error}"))?;
            if !regex.is_match(value) {
                return Err("password does not match the consumer format".into());
            }
        }
        Ok(())
    }
}
