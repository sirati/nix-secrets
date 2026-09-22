use super::*;

struct ScriptedRandom {
    input: Vec<u8>,
    offset: usize,
}

impl ScriptedRandom {
    fn new(input: impl Into<Vec<u8>>) -> Self {
        Self {
            input: input.into(),
            offset: 0,
        }
    }
}

impl RandomSource for ScriptedRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        let end = self.offset + destination.len();
        destination.copy_from_slice(self.input.get(self.offset..end).ok_or(Error::Randomness)?);
        self.offset = end;
        Ok(())
    }
}

fn le(values: &[u64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

#[test]
fn password_rejects_the_biased_tail_before_selecting() {
    // 2^64 mod 3 is one. Zero must be rejected; three then maps to index zero.
    let mut random = ScriptedRandom::new(le(&[0, 3]));
    let result = generate_with(
        &GenerationPolicy::Password {
            length: 1,
            alphabet: "abc".into(),
        },
        &mut random,
    )
    .unwrap();
    assert_eq!(&*result, b"a");
    assert_eq!(random.offset, 16);
}

#[test]
fn accepted_domain_has_no_modulo_remainder() {
    for bound in 1_u64..=4096 {
        let rejected = bound.wrapping_neg() % bound;
        let accepted = (u128::from(u64::MAX) + 1) - u128::from(rejected);
        assert_eq!(accepted % u128::from(bound), 0);
    }
}

#[test]
fn password_supports_unique_unicode_characters() {
    let mut random = ScriptedRandom::new(le(&[3, 1, 2]));
    let result = generate_with(
        &GenerationPolicy::Password {
            length: 3,
            alphabet: "aβ🦀".into(),
        },
        &mut random,
    )
    .unwrap();
    assert_eq!(std::str::from_utf8(&result).unwrap(), "aβ🦀");
}

#[test]
fn passphrase_uses_configured_words_and_exact_separator() {
    let mut random = ScriptedRandom::new(le(&[2, 3, 1]));
    let policy = GenerationPolicy::Passphrase {
        words: 3,
        separator: "::".into(),
        word_list: vec!["amber".into(), "birch".into(), "cedar".into()],
    };
    assert_eq!(
        &*generate_with(&policy, &mut random).unwrap(),
        b"cedar::amber::birch"
    );
}

#[test]
fn byte_encodings_are_exact() {
    let cases = [
        (ByteEncoding::Raw, &b"\xfb\xef\xff"[..]),
        (ByteEncoding::HexLower, &b"fbefff"[..]),
        (ByteEncoding::Base64, &b"++//"[..]),
        (ByteEncoding::Base64UrlUnpadded, &b"--__"[..]),
    ];
    for (encoding, expected) in cases {
        let mut random = ScriptedRandom::new([0xfb, 0xef, 0xff]);
        let policy = GenerationPolicy::Bytes {
            length: 3,
            encoding,
        };
        assert_eq!(&*generate_with(&policy, &mut random).unwrap(), expected);
    }
}

#[test]
fn base64url_is_unpadded_for_partial_groups() {
    let mut random = ScriptedRandom::new([0xff]);
    let policy = GenerationPolicy::Bytes {
        length: 1,
        encoding: ByteEncoding::Base64UrlUnpadded,
    };
    assert_eq!(&*generate_with(&policy, &mut random).unwrap(), b"_w");
}

#[test]
fn invalid_and_excessive_policies_are_rejected_before_randomness() {
    let mut random = ScriptedRandom::new([]);
    let duplicate = GenerationPolicy::Password {
        length: 10,
        alphabet: "aba".into(),
    };
    assert_eq!(
        generate_with(&duplicate, &mut random).unwrap_err(),
        Error::DuplicateAlphabetCharacter
    );
    let excessive = GenerationPolicy::Bytes {
        length: MAX_OUTPUT_BYTES,
        encoding: ByteEncoding::HexLower,
    };
    assert_eq!(
        generate_with(&excessive, &mut random).unwrap_err(),
        Error::Limit("generated output")
    );
}

#[test]
fn operating_system_source_produces_the_requested_size() {
    let result = generate(&GenerationPolicy::Bytes {
        length: 32,
        encoding: ByteEncoding::Raw,
    })
    .unwrap();
    assert_eq!(result.len(), 32);
}

#[test]
fn bundled_eff_large_list_is_complete_and_unique() {
    let mut words = eff_large_words();
    assert_eq!(words.len(), 7_776);
    words.sort_unstable();
    words.dedup();
    assert_eq!(words.len(), 7_776);
}
