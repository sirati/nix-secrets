//! Formats of values a target may generate for itself when they are unset.
//!
//! A stored leaf is generated during deployment only when its exact format is
//! known: a `valueType = "password"` leaf uses the password generator under its
//! consumer constraints, and any other leaf must declare `valueGenerator`.
//! The target generates, installs, and encrypts the value; the operator only
//! receives the ciphertext. These rules therefore run on both sides, and the
//! target's [`DeployGenerator::fingerprint`] must match the operator's.

use crate::generator::{ByteEncoding, GeneratorOptions, RandomSource};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{ConsumerConstraints, SecretKind, SecretSpec, ValueType};

/// The schema's `valueGenerator` attribute.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ValueGenerator {
    /// `prefix`, then uniform random bytes in `encoding`, then `suffix`.
    /// Prefix and suffix are public literal text, such as a configuration
    /// key name or a trailing newline.
    #[serde(rename = "random-bytes")]
    RandomBytes {
        bytes: usize,
        encoding: RandomEncoding,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        prefix: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        suffix: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RandomEncoding {
    /// Standard alphabet with padding.
    #[serde(rename = "base64")]
    Base64,
    /// URL-safe alphabet without padding.
    #[serde(rename = "base64url")]
    Base64UrlUnpadded,
    /// Lowercase hexadecimal.
    #[serde(rename = "hex")]
    HexLower,
}

pub const MIN_RANDOM_BYTES: usize = 16;
pub const MAX_RANDOM_BYTES: usize = 1024;
pub const MAX_AFFIX_BYTES: usize = 1024;
const PASSWORD_ALPHABETS: [&str; 5] = [
    concat!(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "!#$%&()*+,-./:;<=>?@[]^_{|}~"
    ),
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
];

impl ValueGenerator {
    pub fn validate_definition(&self) -> Result<(), String> {
        match self {
            Self::RandomBytes {
                bytes,
                prefix,
                suffix,
                ..
            } => {
                if !(MIN_RANDOM_BYTES..=MAX_RANDOM_BYTES).contains(bytes) {
                    return Err(format!(
                        "random-bytes generator needs {MIN_RANDOM_BYTES} through {MAX_RANDOM_BYTES} bytes"
                    ));
                }
                for affix in [prefix, suffix] {
                    if affix.len() > MAX_AFFIX_BYTES || affix.contains('\0') {
                        return Err(format!(
                            "random-bytes prefix and suffix must be at most {MAX_AFFIX_BYTES} bytes without NUL"
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}

/// The generator a target uses for one leaf, including everything that
/// determines the output format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind")]
pub enum DeployGenerator {
    #[serde(rename = "password")]
    Password {
        #[serde(skip_serializing_if = "Option::is_none")]
        constraints: Option<ConsumerConstraints>,
    },
    #[serde(rename = "value")]
    Declared { generator: ValueGenerator },
}

impl DeployGenerator {
    /// Canonical description compared between the operator's schema and the
    /// target's manifest before anything is generated.
    pub fn fingerprint(&self) -> String {
        serde_json::to_string(self).expect("generator descriptions serialize")
    }

    /// A short label for approval dialogs.
    pub fn label(&self) -> String {
        match self {
            Self::Password { .. } => "password".into(),
            Self::Declared {
                generator:
                    ValueGenerator::RandomBytes {
                        bytes,
                        encoding,
                        prefix,
                        suffix,
                    },
            } => {
                let encoding = match encoding {
                    RandomEncoding::Base64 => "base64",
                    RandomEncoding::Base64UrlUnpadded => "base64url",
                    RandomEncoding::HexLower => "hex",
                };
                let framed = if prefix.is_empty() && suffix.is_empty() {
                    ""
                } else {
                    ", framed"
                };
                format!("{bytes} random bytes, {encoding}{framed}")
            }
        }
    }

    /// Produces a value from `random`. Targets pass their kernel source;
    /// tests pass a scripted one.
    pub fn generate_with(
        &self,
        random: &mut impl RandomSource,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        match self {
            Self::Password { constraints } => password(constraints.as_ref(), random),
            Self::Declared { generator } => {
                generator.validate_definition()?;
                let ValueGenerator::RandomBytes {
                    bytes,
                    encoding,
                    prefix,
                    suffix,
                } = generator;
                let encoded = crate::generator::generate_with(
                    &GeneratorOptions::Bytes {
                        length: *bytes,
                        encoding: match encoding {
                            RandomEncoding::Base64 => ByteEncoding::Base64,
                            RandomEncoding::Base64UrlUnpadded => ByteEncoding::Base64UrlUnpadded,
                            RandomEncoding::HexLower => ByteEncoding::HexLower,
                        },
                    },
                    random,
                )
                .map_err(|error| error.to_string())?;
                let mut output = Zeroizing::new(Vec::with_capacity(
                    prefix.len() + encoded.len() + suffix.len(),
                ));
                output.extend_from_slice(prefix.as_bytes());
                output.extend_from_slice(&encoded);
                output.extend_from_slice(suffix.as_bytes());
                Ok(output)
            }
        }
    }
}

fn password(
    constraints: Option<&ConsumerConstraints>,
    random: &mut impl RandomSource,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let minimum = constraints
        .and_then(|c| c.cannot_handle_shorter_than)
        .unwrap_or(0);
    let maximum = constraints
        .and_then(|c| c.cannot_handle_longer_than)
        .unwrap_or(usize::MAX);
    if minimum > 256 || maximum == 0 {
        return Err("consumer length limits cannot be met by the password generator".into());
    }
    let length = 32_usize.max(minimum).min(maximum);
    for alphabet in PASSWORD_ALPHABETS {
        let options = GeneratorOptions::Password {
            length,
            alphabet: alphabet.into(),
        };
        for _ in 0..16 {
            let value = crate::generator::generate_with(&options, random)
                .map_err(|error| error.to_string())?;
            if constraints.is_none_or(|c| {
                std::str::from_utf8(&value).is_ok_and(|text| c.accepts(text).is_ok())
            }) {
                return Ok(value);
            }
        }
    }
    Err("the password generator could not meet the consumer format".into())
}

/// Why a stored leaf cannot be generated during deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotGeneratable {
    /// `externalInputRequired = true`.
    ExternalInput,
    /// `generateOnDeploy = false`, for example a value shared with a leaf
    /// on another host.
    OptedOut,
    /// Public information is attested, never generated.
    PublicInfo,
    /// Neither a password nor a declared `valueGenerator`.
    UnknownFormat,
}

impl NotGeneratable {
    pub fn reason(self) -> &'static str {
        match self {
            Self::ExternalInput => "external input",
            Self::OptedOut => "generateOnDeploy = false",
            Self::PublicInfo => "public information",
            Self::UnknownFormat => "no valueGenerator",
        }
    }
}

/// The generator a target may use for this stored leaf when it is unset.
pub fn deployment_generator(spec: &SecretSpec) -> Result<DeployGenerator, NotGeneratable> {
    decide(
        &spec.kind,
        spec.external_input_required,
        spec.generate_on_deploy,
        spec.value_generator.as_ref(),
        spec.value_type,
        spec.consumer_constraints.as_ref(),
    )
}

impl super::SecretLeaf {
    /// [`deployment_generator`] for a manifest node.
    pub fn deployment_generator(&self) -> Result<DeployGenerator, NotGeneratable> {
        decide(
            &self.kind,
            self.external_input_required,
            self.generate_on_deploy,
            self.value_generator.as_ref(),
            self.value_type,
            self.consumer_constraints.as_ref(),
        )
    }
}

fn decide(
    kind: &SecretKind,
    external_input_required: bool,
    generate_on_deploy: bool,
    value_generator: Option<&ValueGenerator>,
    value_type: Option<ValueType>,
    constraints: Option<&ConsumerConstraints>,
) -> Result<DeployGenerator, NotGeneratable> {
    if matches!(kind, SecretKind::PublicInfo) {
        return Err(NotGeneratable::PublicInfo);
    }
    if external_input_required {
        return Err(NotGeneratable::ExternalInput);
    }
    if !generate_on_deploy {
        return Err(NotGeneratable::OptedOut);
    }
    if let Some(generator) = value_generator {
        return Ok(DeployGenerator::Declared {
            generator: generator.clone(),
        });
    }
    if value_type == Some(ValueType::Password) {
        return Ok(DeployGenerator::Password {
            constraints: constraints.cloned(),
        });
    }
    Err(NotGeneratable::UnknownFormat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{Error, RandomSource};

    struct Counting(u8);
    impl RandomSource for Counting {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), Error> {
            for byte in destination {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn declared(
        bytes: usize,
        encoding: RandomEncoding,
        prefix: &str,
        suffix: &str,
    ) -> DeployGenerator {
        DeployGenerator::Declared {
            generator: ValueGenerator::RandomBytes {
                bytes,
                encoding,
                prefix: prefix.into(),
                suffix: suffix.into(),
            },
        }
    }

    #[test]
    fn random_bytes_formats_are_exact() {
        let hex = declared(16, RandomEncoding::HexLower, "", "")
            .generate_with(&mut Counting(0))
            .unwrap();
        assert_eq!(hex.as_slice(), b"000102030405060708090a0b0c0d0e0f");
        let url = declared(32, RandomEncoding::Base64UrlUnpadded, "", "")
            .generate_with(&mut Counting(0xf0))
            .unwrap();
        assert_eq!(url.len(), 43);
        assert!(!url.contains(&b'='));
        assert!(
            url.iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        );
        let standard = declared(32, RandomEncoding::Base64, "", "")
            .generate_with(&mut Counting(0))
            .unwrap();
        assert_eq!(standard.len(), 44);
        assert!(standard.ends_with(b"="));
    }

    #[test]
    fn framing_wraps_the_encoded_value() {
        let knot = declared(
            32,
            RandomEncoding::Base64,
            "key:\n  - id: dns-transfer\n    algorithm: hmac-sha256\n    secret: ",
            "\n",
        )
        .generate_with(&mut Counting(0))
        .unwrap();
        let text = std::str::from_utf8(&knot).unwrap();
        assert!(text.starts_with("key:\n  - id: dns-transfer\n"));
        let secret = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("secret: "))
            .unwrap();
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(secret)
                .unwrap(),
            (0..32).collect::<Vec<u8>>()
        );
        assert!(text.ends_with("=\n"));
        let env = declared(24, RandomEncoding::Base64UrlUnpadded, "CIPHER_PASS=", "\n")
            .generate_with(&mut Counting(0))
            .unwrap();
        assert!(env.starts_with(b"CIPHER_PASS=") && env.ends_with(b"\n"));
    }

    #[test]
    fn definitions_are_bounded() {
        let bad = |bytes, prefix: &str| {
            ValueGenerator::RandomBytes {
                bytes,
                encoding: RandomEncoding::HexLower,
                prefix: prefix.into(),
                suffix: String::new(),
            }
            .validate_definition()
            .is_err()
        };
        assert!(bad(15, ""));
        assert!(bad(1025, ""));
        assert!(bad(32, "a\0b"));
        assert!(bad(32, &"x".repeat(MAX_AFFIX_BYTES + 1)));
        assert!(!bad(16, "prefix="));
    }

    #[test]
    fn password_generator_obeys_constraints() {
        let constraints = ConsumerConstraints {
            cannot_handle_shorter_than: Some(8),
            cannot_handle_longer_than: Some(12),
            matching_regex: Some("[a-z]+".into()),
        };
        let value = DeployGenerator::Password {
            constraints: Some(constraints.clone()),
        }
        .generate_with(&mut crate::generator::OsRandom)
        .unwrap();
        let text = std::str::from_utf8(&value).unwrap();
        assert_eq!(text.len(), 12);
        assert!(constraints.accepts(text).is_ok());
    }

    #[test]
    fn fingerprint_covers_format_and_constraints() {
        let a = DeployGenerator::Password { constraints: None };
        let b = DeployGenerator::Password {
            constraints: Some(ConsumerConstraints {
                cannot_handle_longer_than: Some(20),
                ..Default::default()
            }),
        };
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_ne!(
            declared(32, RandomEncoding::Base64, "", "").fingerprint(),
            declared(32, RandomEncoding::Base64, "", "\n").fingerprint()
        );
    }
}
