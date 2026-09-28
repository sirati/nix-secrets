//! A single client-approved SSH authentication signature. This is separate
//! from the Git agent relay: no private key or general agent access is sent.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureRequest {
    pub public_key: String,
    /// Caller-declared destination. The client cannot verify the host from
    /// an agent challenge; the UI must identify this as an unvalidated claim.
    pub destination: String,
    pub message: Vec<u8>,
}

fn string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let length = input.get(..4).ok_or("truncated SSH string")?;
    let length = u32::from_be_bytes(length.try_into().unwrap()) as usize;
    let value = input.get(4..4 + length).ok_or("truncated SSH string")?;
    *input = &input[4 + length..];
    Ok(value)
}

pub fn put_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

pub fn key_blob(public_key: &str) -> Result<Vec<u8>, String> {
    let mut fields = public_key.split_whitespace();
    if fields.next() != Some("ssh-ed25519") {
        return Err("SSH authentication relay currently requires an Ed25519 key".into());
    }
    let blob = STANDARD
        .decode(fields.next().ok_or("missing public key")?)
        .map_err(|_| "invalid public key encoding")?;
    let mut rest = blob.as_slice();
    if string(&mut rest)? != b"ssh-ed25519" || string(&mut rest)?.len() != 32 || !rest.is_empty() {
        return Err("invalid Ed25519 public key".into());
    }
    Ok(blob)
}

impl SignatureRequest {
    pub fn validate(&self) -> Result<(), String> {
        let (user, host) = self
            .destination
            .split_once('@')
            .ok_or("destination must be user@host")?;
        if user.is_empty()
            || user.len() > 64
            || host.is_empty()
            || host.len() > 253
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err("invalid SSH destination".into());
        }
        if self.message.len() > crate::git::agent::MAX_MESSAGE {
            return Err("SSH agent request is too large".into());
        }
        let key = key_blob(&self.public_key)?;
        let mut rest = self.message.as_slice();
        if rest.first() != Some(&13) {
            return Err("only an SSH signing request is accepted".into());
        }
        rest = &rest[1..];
        if string(&mut rest)? != key {
            return Err("request asks for another SSH key".into());
        }
        let mut data = string(&mut rest)?;
        if rest != [0, 0, 0, 0] {
            return Err("unsupported SSH signing flags".into());
        }
        if !matches!(string(&mut data)?.len(), 32 | 64) {
            return Err("invalid SSH session identifier".into());
        }
        if data.first() != Some(&50) {
            return Err("only SSH user authentication may be signed".into());
        }
        data = &data[1..];
        if string(&mut data)? != user.as_bytes() || string(&mut data)? != b"ssh-connection" {
            return Err("SSH authentication destination or method differs".into());
        }
        let host_bound = match string(&mut data)? {
            b"publickey" => false,
            b"publickey-hostbound-v00@openssh.com" => true,
            _ => return Err("only SSH public-key authentication may be signed".into()),
        };
        if data.first() != Some(&1) {
            return Err("SSH authentication must request a signature".into());
        }
        data = &data[1..];
        if string(&mut data)? != b"ssh-ed25519" || string(&mut data)? != key {
            return Err("SSH authentication key differs".into());
        }
        if host_bound {
            ssh_key::PublicKey::from_bytes(string(&mut data)?)
                .map_err(|_| "malformed SSH server host key")?;
        }
        if !data.is_empty() {
            return Err("SSH authentication key differs or has trailing data".into());
        }
        Ok(())
    }
}

/// Only lists the one configured public key; no client agent enumeration.
pub fn identities(public_key: &str) -> Result<Vec<u8>, String> {
    let key = key_blob(public_key)?;
    let mut reply = vec![12, 0, 0, 0, 1];
    put_string(&mut reply, &key);
    put_string(&mut reply, b"nix-secrets approved SSH authentication key");
    Ok(reply)
}

/// Called on the TUI machine after approval, with validation repeated there.
pub fn sign(socket: &Path, request: &SignatureRequest) -> Result<Vec<u8>, String> {
    request.validate()?;
    let mut stream =
        UnixStream::connect(socket).map_err(|e| format!("client SSH agent unavailable: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    crate::git::agent::write_message(&mut stream, &request.message).map_err(|e| e.to_string())?;
    let reply = crate::git::agent::read_message(&mut stream)
        .map_err(|e| e.to_string())?
        .ok_or("client SSH agent closed the connection")?;
    validate_reply(&reply)?;
    Ok(reply)
}

pub fn validate_reply(reply: &[u8]) -> Result<(), String> {
    if reply.first() != Some(&14) {
        return Err("client SSH agent refused the authentication signature".into());
    }
    let mut rest = &reply[1..];
    let mut signature = string(&mut rest)?;
    if !rest.is_empty()
        || string(&mut signature)? != b"ssh-ed25519"
        || string(&mut signature)?.len() != 64
        || !signature.is_empty()
    {
        return Err("malformed SSH signature reply".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> SignatureRequest {
        request_with_method(b"publickey", false)
    }
    fn request_with_method(method: &[u8], host_bound: bool) -> SignatureRequest {
        let mut key = Vec::new();
        put_string(&mut key, b"ssh-ed25519");
        put_string(&mut key, &[3; 32]);
        let mut data = Vec::new();
        put_string(&mut data, &[4; 32]);
        data.push(50);
        for value in [b"update".as_slice(), b"ssh-connection", method] {
            put_string(&mut data, value);
        }
        data.push(1);
        put_string(&mut data, b"ssh-ed25519");
        put_string(&mut data, &key);
        if host_bound {
            put_string(&mut data, &key);
        }
        let mut message = vec![13];
        put_string(&mut message, &key);
        put_string(&mut message, &data);
        message.extend_from_slice(&[0; 4]);
        SignatureRequest {
            public_key: format!("ssh-ed25519 {}", STANDARD.encode(key)),
            destination: "update@ns1.lamk.eu".into(),
            message,
        }
    }
    #[test]
    fn only_the_selected_key_and_user_auth_challenge_pass() {
        let good = request();
        good.validate().unwrap();
        request_with_method(b"publickey-hostbound-v00@openssh.com", true)
            .validate()
            .unwrap();
        assert!(
            request_with_method(b"publickey-hostbound-v00@openssh.com", false)
                .validate()
                .is_err()
        );
        assert!(request_with_method(b"arbitrary-method", false)
            .validate()
            .is_err());
        assert!(crate::git::agent::permitted(&good.message).is_err());
        let mut other = good.clone();
        other.destination = "root@ns1.lamk.eu".into();
        assert!(other.validate().is_err());
        let mut other = good.clone();
        other.message[20] ^= 1;
        assert!(other.validate().is_err());
        let mut other = good.clone();
        other.message.push(0);
        assert!(other.validate().is_err());
        for kind in [11, 17, 18, 22, 27] {
            let mut other = good.clone();
            other.message[0] = kind;
            assert!(other.validate().is_err());
        }
        for length in 0..good.message.len() {
            let mut other = good.clone();
            other.message.truncate(length);
            assert!(other.validate().is_err());
        }
    }
    #[test]
    fn reply_must_be_an_ed25519_signature() {
        let mut signature = Vec::new();
        put_string(&mut signature, b"ssh-ed25519");
        put_string(&mut signature, &[7; 64]);
        let mut reply = vec![14];
        put_string(&mut reply, &signature);
        validate_reply(&reply).unwrap();
        assert!(validate_reply(&[5]).is_err());
        reply.push(0);
        assert!(validate_reply(&reply).is_err());
    }
}
