use ssh_key::{PrivateKey, PublicKey};

pub(super) fn validate(content_type: Option<&str>, value: &[u8]) -> Result<(), String> {
    match content_type {
        Some("openssh-private-key") => {
            let text = std::str::from_utf8(value).map_err(|_| "SSH private key must be UTF-8")?;
            let key = PrivateKey::from_openssh(text).map_err(|_| "invalid OpenSSH private key")?;
            if key.is_encrypted() {
                return Err("OpenSSH private key requires an interactive passphrase".into());
            }
        }
        Some("openssh-public-key") => {
            let text = std::str::from_utf8(value).map_err(|_| "SSH public key must be UTF-8")?;
            PublicKey::from_openssh(text.trim()).map_err(|_| "invalid OpenSSH public key")?;
        }
        Some("named-ssh-ed25519-public-keys") => validate_named(value)?,
        _ => {}
    }
    Ok(())
}

pub(super) fn derive_public(
    content_type: Option<&str>,
    value: &[u8],
) -> Result<Option<String>, String> {
    if content_type != Some("openssh-private-key") {
        return Ok(None);
    }
    let text = std::str::from_utf8(value).map_err(|_| "SSH private key must be UTF-8")?;
    let private = PrivateKey::from_openssh(text).map_err(|_| "invalid OpenSSH private key")?;
    if private.is_encrypted() {
        return Err("OpenSSH private key requires an interactive passphrase".into());
    }
    private
        .public_key()
        .to_openssh()
        .map(Some)
        .map_err(|_| "cannot derive OpenSSH public key".into())
}

fn validate_named(value: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(value).map_err(|_| "SSH key inventory must be UTF-8")?;
    if text.len() > 128 * 1024 {
        return Err("SSH key inventory is too large".into());
    }
    let mut names = std::collections::BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (name, key) = line.split_once(' ').ok_or("invalid named SSH key line")?;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !names.insert(name)
        {
            return Err("invalid or duplicate named SSH key".into());
        }
        let parsed =
            PublicKey::from_openssh(key).map_err(|_| "invalid named OpenSSH public key")?;
        if parsed.algorithm() != ssh_key::Algorithm::Ed25519 {
            return Err("named SSH key must be Ed25519".into());
        }
    }
    if names.is_empty() || names.len() > 128 {
        return Err("invalid number of named SSH keys".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_public_private_and_named_keys() {
        assert!(validate(Some("openssh-private-key"), b"not a key").is_err());
        assert!(validate(Some("openssh-public-key"), b"ssh-ed25519 AAAA").is_err());
        assert!(validate(
            Some("named-ssh-ed25519-public-keys"),
            b"name ssh-ed25519 AAAA"
        )
        .is_err());
    }
}
