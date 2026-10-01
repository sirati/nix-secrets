//! Public artifact manifests and detached signatures. Private keys never cross
//! this protocol; the attached frontend owns approval, hashing and signing.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024 * 1024;
pub const REQUIRED_ROLES: [&str; 5] = [
    "generation-image",
    "boot-config",
    "gen-kernel",
    "gen-initrd",
    "rescue-sfs",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub role: String,
    pub path: String,
    pub sha512: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub artifacts: Vec<Artifact>,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if !(5..=6).contains(&self.artifacts.len()) {
            return Err("artifact batch requires five roles and an optional network stage".into());
        }
        let mut roles = BTreeSet::new();
        for artifact in &self.artifacts {
            if !REQUIRED_ROLES.contains(&artifact.role.as_str()) && artifact.role != "network-stage"
            {
                return Err("unknown artifact role".into());
            }
            if !roles.insert(artifact.role.as_str()) {
                return Err("duplicate artifact role".into());
            }
            if !hex(&artifact.sha512, 128) {
                return Err("artifact SHA512 must be 128 lowercase hexadecimal characters".into());
            }
            if artifact.size == 0 || artifact.size > MAX_ARTIFACT_BYTES {
                return Err("artifact size outside permitted bounds".into());
            }
            if !artifact.path.starts_with("/nix/store/")
                || artifact.path.len() > 4096
                || artifact.path.contains('\0')
            {
                return Err("signing accepts immutable Nix store artifacts only".into());
            }
        }
        if REQUIRED_ROLES.iter().any(|role| !roles.contains(role)) {
            return Err("missing required artifact role".into());
        }
        Ok(())
    }
}

pub fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub identifier: String,
    pub host: String,
    pub public_key_sha256: String,
    pub manifest: Manifest,
}

impl SigningRequest {
    pub fn validate(&self) -> Result<(), String> {
        let path = crate::SecretPath::parse(&self.identifier).map_err(|error| error.to_string())?;
        if self.host.is_empty()
            || self.host.len() > 253
            || !self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !self
                .identifier
                .starts_with(&format!("{}.services.", self.host))
        {
            return Err("signing key must belong to the declared host".into());
        }
        let _ = path;
        if !hex(&self.public_key_sha256, 64) {
            return Err("invalid signing public-key fingerprint".into());
        }
        self.manifest.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    pub role: String,
    pub sha512: String,
    pub size: u64,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signatures {
    pub signatures: Vec<DetachedSignature>,
}

impl Signatures {
    pub fn validate(&self, manifest: &Manifest) -> Result<(), String> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        if self.signatures.len() != manifest.artifacts.len() {
            return Err("missing or extra detached signature".into());
        }
        let mut roles = BTreeSet::new();
        for signature in &self.signatures {
            if !roles.insert(&signature.role) {
                return Err("duplicate detached signature".into());
            }
            let artifact = manifest
                .artifacts
                .iter()
                .find(|artifact| artifact.role == signature.role)
                .ok_or("unasked detached signature")?;
            if artifact.sha512 != signature.sha512 || artifact.size != signature.size {
                return Err("detached signature does not match approved artifact".into());
            }
            if signature.signature_base64.len() > 8192 {
                return Err("oversized detached signature".into());
            }
            let decoded = STANDARD
                .decode(&signature.signature_base64)
                .map_err(|_| "malformed detached signature")?;
            if !decoded.starts_with(b"NMBLSIG1") || !(3000..=6000).contains(&decoded.len()) {
                return Err("invalid detached NMBL sidecar".into());
            }
        }
        Ok(())
    }
}
