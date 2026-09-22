use serde::{Deserialize, Serialize};

use super::{SchemaError, SecretPath};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GenerationPolicy {
    RandomPassword {
        length: u16,
        alphabet: PasswordAlphabet,
    },
    RandomPassphrase {
        words: u8,
        separator: PassphraseSeparator,
        #[serde(rename = "wordList")]
        word_list: PassphraseWordList,
    },
    RandomBytes {
        bytes: u16,
        encoding: ByteEncoding,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PasswordAlphabet {
    Alphanumeric,
    AsciiSafe,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PassphraseSeparator {
    Hyphen,
    Underscore,
    Space,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PassphraseWordList {
    EffLarge,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ByteEncoding {
    Base64urlUnpadded,
    Base64,
    Hex,
}

impl GenerationPolicy {
    pub(super) fn validate(&self, path: &SecretPath) -> Result<(), SchemaError> {
        let valid = match self {
            Self::RandomPassword { length, .. } => (16..=256).contains(length),
            Self::RandomPassphrase { words, .. } => (6..=24).contains(words),
            Self::RandomBytes { bytes, .. } => (16..=4096).contains(bytes),
        };
        if valid {
            Ok(())
        } else {
            Err(SchemaError::InvalidGeneration(path.clone()))
        }
    }
}
