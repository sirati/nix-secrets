use crate::ui::GenerateKind;
use nix_secrets_core::{ConsumerConstraints, ValueType};
use zeroize::Zeroizing;

pub(super) fn validate_password_value(
    value_type: Option<ValueType>,
    constraints: Option<&ConsumerConstraints>,
    value: &[u8],
) -> Result<(), String> {
    if value_type != Some(ValueType::Password) {
        return Ok(());
    }
    let text = std::str::from_utf8(value).map_err(|_| "password must be UTF-8".to_string())?;
    if let Some(constraints) = constraints {
        constraints.accepts(text)?;
    }
    Ok(())
}

pub(super) fn generate_compatible(
    kind: GenerateKind,
    constraints: Option<&ConsumerConstraints>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let minimum = constraints
        .and_then(|c| c.cannot_handle_shorter_than)
        .unwrap_or(0);
    let maximum = constraints
        .and_then(|c| c.cannot_handle_longer_than)
        .unwrap_or(usize::MAX);
    let candidates: Vec<crate::generator::GeneratorOptions> = match kind {
        GenerateKind::Password => {
            if minimum > 256 || maximum == 0 {
                return Err(
                    "consumer length limits cannot be met by the password generator".into(),
                );
            }
            let length = 32_usize.max(minimum).min(maximum);
            [
                concat!(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    "!#$%&()*+,-./:;<=>?@[]^_{|}~"
                ),
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "abcdefghijklmnopqrstuvwxyz",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "0123456789",
            ]
            .into_iter()
            .map(|alphabet| crate::generator::GeneratorOptions::Password {
                length,
                alphabet: alphabet.into(),
            })
            .collect()
        }
        GenerateKind::Passphrase => {
            let words = crate::generator::eff_large_words();
            std::iter::once(8)
                .chain((2..=24).filter(|count| *count != 8))
                .map(|count| crate::generator::GeneratorOptions::Passphrase {
                    words: count,
                    separator: "-".into(),
                    word_list: words.clone(),
                })
                .collect()
        }
    };
    for options in candidates {
        for _ in 0..16 {
            let value = crate::generator::generate(&options).map_err(|error| error.to_string())?;
            let suffixes: &[&str] = if kind == GenerateKind::Passphrase {
                &["", "1", "!", "-1!", "A1!", "_A1!", ".A1!"]
            } else {
                &[""]
            };
            for suffix in suffixes {
                let mut candidate = value.clone();
                candidate.extend_from_slice(suffix.as_bytes());
                if constraints.is_none_or(|c| {
                    std::str::from_utf8(&candidate).is_ok_and(|text| c.accepts(text).is_ok())
                }) {
                    return Ok(candidate);
                }
            }
        }
    }
    Err("the selected generator could not meet the consumer format".into())
}

#[cfg(test)]
mod value_tests {
    use super::*;

    #[test]
    fn generator_respects_consumer_length_and_format() {
        let constraints = ConsumerConstraints {
            cannot_handle_shorter_than: Some(8),
            cannot_handle_longer_than: Some(12),
            matching_regex: Some("[A-Za-z0-9]+".into()),
        };
        let value = generate_compatible(GenerateKind::Password, Some(&constraints)).unwrap();
        let value = std::str::from_utf8(&value).unwrap();
        assert!(constraints.accepts(value).is_ok());
        assert_eq!(value.len(), 12);
    }

    #[test]
    fn passphrase_is_operator_choice() {
        let value = generate_compatible(GenerateKind::Passphrase, None).unwrap();
        assert_eq!(value.iter().filter(|byte| **byte == b'-').count(), 7);
    }

    #[test]
    fn passphrase_can_satisfy_consumer_special_character_suffix() {
        let constraints = ConsumerConstraints {
            cannot_handle_shorter_than: Some(10),
            cannot_handle_longer_than: Some(100),
            matching_regex: Some("[a-z-]+[0-9]!".into()),
        };
        let value = generate_compatible(GenerateKind::Passphrase, Some(&constraints)).unwrap();
        let text = std::str::from_utf8(&value).unwrap();
        assert!(text.ends_with("1!"));
        assert!(constraints.accepts(text).is_ok());
    }

    #[test]
    fn pasted_passwords_obey_the_same_consumer_limits() {
        let constraints = ConsumerConstraints {
            cannot_handle_shorter_than: Some(3),
            cannot_handle_longer_than: Some(5),
            matching_regex: Some("[a-z]+".into()),
        };
        assert!(
            validate_password_value(Some(ValueType::Password), Some(&constraints), b"abc").is_ok()
        );
        assert!(
            validate_password_value(Some(ValueType::Password), Some(&constraints), b"ab").is_err()
        );
        assert!(
            validate_password_value(Some(ValueType::Password), Some(&constraints), b"ABC").is_err()
        );
        assert!(
            validate_password_value(Some(ValueType::Password), Some(&constraints), b"\xff")
                .is_err()
        );
    }
}
