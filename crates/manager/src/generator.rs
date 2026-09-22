//! Secret generation with an injectable random source.

use base64::engine::general_purpose;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_ALPHABET_CHARS: usize = 4096;
const MAX_WORDS: usize = 4096;
const MAX_WORD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteEncoding {
    Raw,
    HexLower,
    Base64,
    Base64UrlUnpadded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerationPolicy {
    Password {
        length: usize,
        alphabet: String,
    },
    Passphrase {
        words: usize,
        separator: String,
        word_list: Vec<String>,
    },
    Bytes {
        length: usize,
        encoding: ByteEncoding,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Empty(&'static str),
    DuplicateAlphabetCharacter,
    Limit(&'static str),
    Randomness,
    Encoding,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(formatter, "{field} must not be empty"),
            Self::DuplicateAlphabetCharacter => {
                formatter.write_str("password alphabet contains duplicate characters")
            }
            Self::Limit(field) => write!(formatter, "{field} exceeds its safety limit"),
            Self::Randomness => formatter.write_str("operating-system randomness failed"),
            Self::Encoding => formatter.write_str("output encoding failed"),
        }
    }
}

impl std::error::Error for Error {}

pub trait RandomSource {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), Error>;
}

#[derive(Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(destination).map_err(|_| Error::Randomness)
    }
}

pub fn generate(policy: &GenerationPolicy) -> Result<Zeroizing<Vec<u8>>, Error> {
    generate_with(policy, &mut OsRandom)
}

pub fn eff_large_words() -> Vec<String> {
    include_str!("generator/eff-large.words")
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect()
}

pub fn generate_with(
    policy: &GenerationPolicy,
    random: &mut impl RandomSource,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match policy {
        GenerationPolicy::Password { length, alphabet } => password(*length, alphabet, random),
        GenerationPolicy::Passphrase {
            words,
            separator,
            word_list,
        } => passphrase(*words, separator, word_list, random),
        GenerationPolicy::Bytes { length, encoding } => fixed_bytes(*length, *encoding, random),
    }
}

fn password(
    length: usize,
    alphabet: &str,
    random: &mut impl RandomSource,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    require_nonzero(length, "password length")?;
    let characters: Vec<char> = alphabet.chars().collect();
    require_nonzero(characters.len(), "password alphabet")?;
    if characters.len() > MAX_ALPHABET_CHARS {
        return Err(Error::Limit("password alphabet"));
    }
    let mut unique = characters.clone();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != characters.len() {
        return Err(Error::DuplicateAlphabetCharacter);
    }
    let maximum = length
        .checked_mul(4)
        .ok_or(Error::Limit("password output"))?;
    require_output_bound(maximum)?;
    let mut output = Zeroizing::new(Vec::with_capacity(maximum));
    for _ in 0..length {
        let mut index = uniform_index(characters.len(), random)?;
        let mut encoded = [0_u8; 4];
        output.extend_from_slice(characters[index].encode_utf8(&mut encoded).as_bytes());
        index.zeroize();
        encoded.zeroize();
    }
    Ok(output)
}

fn passphrase(
    count: usize,
    separator: &str,
    words: &[String],
    random: &mut impl RandomSource,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    require_nonzero(count, "passphrase word count")?;
    require_nonzero(words.len(), "passphrase word list")?;
    if count > MAX_WORDS || words.len() > MAX_WORDS {
        return Err(Error::Limit("passphrase words"));
    }
    if words.iter().any(String::is_empty) {
        return Err(Error::Empty("passphrase word"));
    }
    if words.iter().any(|word| word.len() > MAX_WORD_BYTES) {
        return Err(Error::Limit("passphrase word"));
    }
    let longest = words.iter().map(String::len).max().unwrap_or(0);
    let separators = count.saturating_sub(1);
    let maximum = count
        .checked_mul(longest)
        .and_then(|size| size.checked_add(separators.checked_mul(separator.len())?))
        .ok_or(Error::Limit("passphrase output"))?;
    require_output_bound(maximum)?;
    let mut output = Zeroizing::new(Vec::with_capacity(maximum));
    for position in 0..count {
        if position != 0 {
            output.extend_from_slice(separator.as_bytes());
        }
        let mut index = uniform_index(words.len(), random)?;
        output.extend_from_slice(words[index].as_bytes());
        index.zeroize();
    }
    Ok(output)
}

fn fixed_bytes(
    length: usize,
    encoding: ByteEncoding,
    random: &mut impl RandomSource,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    require_nonzero(length, "byte length")?;
    let output_length = encoded_length(length, encoding)?;
    require_output_bound(output_length)?;
    let mut raw = Zeroizing::new(vec![0_u8; length]);
    random.fill(raw.as_mut_slice())?;
    match encoding {
        ByteEncoding::Raw => Ok(raw),
        ByteEncoding::HexLower => Ok(hex_lower(&raw)),
        ByteEncoding::Base64 => encode_base64(&raw, output_length, &general_purpose::STANDARD),
        ByteEncoding::Base64UrlUnpadded => {
            encode_base64(&raw, output_length, &general_purpose::URL_SAFE_NO_PAD)
        }
    }
}

fn uniform_index(bound: usize, random: &mut impl RandomSource) -> Result<usize, Error> {
    let bound = u64::try_from(bound).map_err(|_| Error::Limit("selection domain"))?;
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let mut bytes = Zeroizing::new([0_u8; 8]);
        random.fill(bytes.as_mut())?;
        let mut value = u64::from_le_bytes(*bytes);
        if value >= threshold {
            let index = (value % bound) as usize;
            value.zeroize();
            return Ok(index);
        }
        value.zeroize();
    }
}

fn require_nonzero(value: usize, field: &'static str) -> Result<(), Error> {
    (value != 0).then_some(()).ok_or(Error::Empty(field))
}

fn require_output_bound(length: usize) -> Result<(), Error> {
    (length <= MAX_OUTPUT_BYTES)
        .then_some(())
        .ok_or(Error::Limit("generated output"))
}

fn encoded_length(length: usize, encoding: ByteEncoding) -> Result<usize, Error> {
    let result = match encoding {
        ByteEncoding::Raw => Some(length),
        ByteEncoding::HexLower => length.checked_mul(2),
        ByteEncoding::Base64 => length
            .checked_add(2)
            .and_then(|size| size.checked_div(3))
            .and_then(|size| size.checked_mul(4)),
        ByteEncoding::Base64UrlUnpadded => length
            .checked_mul(4)
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_div(3)),
    };
    result.ok_or(Error::Limit("encoded output"))
}

fn hex_lower(raw: &[u8]) -> Zeroizing<Vec<u8>> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = Zeroizing::new(Vec::with_capacity(raw.len() * 2));
    for byte in raw {
        output.push(DIGITS[usize::from(byte >> 4)]);
        output.push(DIGITS[usize::from(byte & 0x0f)]);
    }
    output
}

fn encode_base64(
    raw: &[u8],
    length: usize,
    engine: &impl base64::Engine,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut output = Zeroizing::new(vec![0_u8; length]);
    let written = engine
        .encode_slice(raw, output.as_mut_slice())
        .map_err(|_| Error::Encoding)?;
    output.truncate(written);
    Ok(output)
}

#[cfg(test)]
mod tests;
