use serde::{Deserialize, Serialize};

pub(crate) const FORMAT_VERSION: u16 = 1;

/// Opaque, serializable storage for one age-encrypted secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSecret {
    pub format_version: u16,
    #[serde(with = "base64_bytes")]
    pub version_id: Vec<u8>,
    pub recipient_ids: Vec<String>,
    #[serde(with = "base64_bytes")]
    pub age_ciphertext: Vec<u8>,
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        STANDARD.decode(value).map_err(serde::de::Error::custom)
    }
}
