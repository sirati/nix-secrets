use crate::DeployError;
use base64::engine::general_purpose::STANDARD;

pub(super) fn validate_named_ssh_keys(contents: &[u8]) -> Result<(), DeployError> {
    use base64::Engine as _;
    let text = std::str::from_utf8(contents)
        .map_err(|_| DeployError::Invalid("public key inventory is not UTF-8".into()))?;
    if text.len() > 128 * 1024 {
        return Err(DeployError::Invalid(
            "public key inventory is too large".into(),
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    let mut count = 0;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        count += 1;
        let mut fields = line.split_ascii_whitespace();
        let (Some(name), Some(algorithm), Some(encoded), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(DeployError::Invalid("invalid named public key line".into()));
        };
        if name.len() > 128
            || name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !names.insert(name)
            || algorithm != "ssh-ed25519"
        {
            return Err(DeployError::Invalid(
                "invalid named public key entry".into(),
            ));
        }
        let blob = STANDARD
            .decode(encoded)
            .map_err(|_| DeployError::Invalid("invalid public key base64".into()))?;
        if blob.len() != 51
            || &blob[..15] != b"\0\0\0\x0bssh-ed25519"
            || &blob[15..19] != b"\0\0\0\x20"
        {
            return Err(DeployError::Invalid("invalid Ed25519 public key".into()));
        }
    }
    if count == 0 || count > 128 {
        return Err(DeployError::Invalid("invalid number of public keys".into()));
    }
    Ok(())
}

#[cfg(test)]
mod named_key_tests {
    use super::validate_named_ssh_keys;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn accepts_only_unique_named_ed25519_keys() {
        let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        blob.extend_from_slice(&[7; 32]);
        let key = format!(
            "node-20260923T120000Z ssh-ed25519 {}\n",
            STANDARD.encode(blob)
        );
        assert!(validate_named_ssh_keys(key.as_bytes()).is_ok());
        assert!(validate_named_ssh_keys(format!("{key}{key}").as_bytes()).is_err());
        assert!(
            validate_named_ssh_keys(key.replace("node-", "node,command=evil-").as_bytes()).is_err()
        );
        assert!(validate_named_ssh_keys(b"node ssh-ed25519 AAAA").is_err());
    }
}
