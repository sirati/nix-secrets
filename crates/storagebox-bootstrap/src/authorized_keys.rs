use crate::Error;

#[derive(Debug, Eq, PartialEq)]
pub enum Merge {
    Unchanged(Vec<u8>),
    Replaced(Vec<u8>),
}

pub fn merge_authorized_keys(
    current: &[u8],
    marker_prefix: &str,
    public_key: &str,
    utc_date: &str,
) -> Result<Merge, Error> {
    if current.len() > 1024 * 1024 || current.contains(&0) || current.contains(&b'\r') {
        return invalid("file is too large or contains forbidden bytes");
    }
    validate_date(utc_date)?;
    let text = std::str::from_utf8(current)
        .map_err(|_| Error::InvalidAuthorizedKeys("file is not UTF-8".into()))?;
    let desired = format!("{public_key} {marker_prefix}{utc_date}");
    let mut lines = Vec::new();
    let mut marker_count = 0;
    let mut already_current = false;
    for line in text.lines() {
        if line.contains(marker_prefix) {
            marker_count += 1;
            validate_marked_line(line, marker_prefix)?;
            already_current = line
                .split_ascii_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
                == public_key;
            continue;
        }
        if line.contains("nix-secrets:")
            && line
                .split_ascii_whitespace()
                .any(|part| part.starts_with(marker_prefix))
        {
            return invalid("malformed task marker");
        }
        lines.push(line.to_owned());
    }
    if marker_count > 1 {
        return invalid("duplicate task markers");
    }
    if already_current {
        return Ok(Merge::Unchanged(current.to_vec()));
    }
    lines.push(desired);
    let mut output = lines.join("\n").into_bytes();
    output.push(b'\n');
    Ok(Merge::Replaced(output))
}

fn validate_marked_line(line: &str, prefix: &str) -> Result<(), Error> {
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    if fields.len() != 3 || !fields[0].starts_with("ssh-") || !fields[2].starts_with(prefix) {
        return invalid("malformed task marker entry");
    }
    validate_date(&fields[2][prefix.len()..])
}

fn validate_date(value: &str) -> Result<(), Error> {
    if value.len() != 10
        || !value.bytes().enumerate().all(|(i, byte)| {
            if i == 4 || i == 7 {
                byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
    {
        return invalid("marker date is not YYYY-MM-DD");
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, Error> {
    Err(Error::InvalidAuthorizedKeys(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "nix-secrets:host:backup:";
    const KEY: &str = "ssh-ed25519 AAAAnew";

    #[test]
    fn preserves_unrelated_and_replaces_one_old_key() {
        let old =
            b"ssh-rsa AAAAother human\nssh-ed25519 AAAAold nix-secrets:host:backup:2025-01-02\n";
        let Merge::Replaced(value) = merge_authorized_keys(old, PREFIX, KEY, "2026-09-22").unwrap()
        else {
            panic!()
        };
        assert_eq!(
            String::from_utf8(value).unwrap(),
            "ssh-rsa AAAAother human\nssh-ed25519 AAAAnew nix-secrets:host:backup:2026-09-22\n"
        );
    }

    #[test]
    fn same_public_key_is_byte_for_byte_idempotent() {
        let current = b"# retained\nssh-ed25519 AAAAnew nix-secrets:host:backup:2025-01-02\n";
        assert_eq!(
            merge_authorized_keys(current, PREFIX, KEY, "2026-09-22").unwrap(),
            Merge::Unchanged(current.to_vec())
        );
    }

    #[test]
    fn duplicate_and_malformed_markers_are_rejected() {
        let duplicate = b"ssh-ed25519 A nix-secrets:host:backup:2025-01-02\nssh-ed25519 B nix-secrets:host:backup:2025-01-03\n";
        assert!(merge_authorized_keys(duplicate, PREFIX, KEY, "2026-09-22").is_err());
        let malformed = b"command=x ssh-ed25519 A nix-secrets:host:backup:2025-01-02\n";
        assert!(merge_authorized_keys(malformed, PREFIX, KEY, "2026-09-22").is_err());
    }
}
