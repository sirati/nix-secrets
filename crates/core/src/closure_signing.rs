//! Public metadata for native Nix store signatures. Private keys stay in the frontend.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const VERSION: u32 = 1;
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PATHS: usize = 4096;
pub const MAX_NAR_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const NIX32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPath {
    pub path: String,
    #[serde(rename = "narHash")]
    pub nar_hash: String,
    #[serde(rename = "narSize")]
    pub nar_size: u64,
    pub references: Vec<String>,
}

pub fn canonical_store_path(path: &str) -> bool {
    let Some(name) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    let bytes = name.as_bytes();
    bytes.len() > 33
        && bytes.len() <= 244
        && bytes[32] == b'-'
        && bytes[..32].iter().all(|b| NIX32.contains(b))
        && bytes[33] != b'.'
        && bytes[33..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"+-._?=".contains(b))
}

impl ManifestPath {
    pub fn validate(&self) -> Result<(), String> {
        if !canonical_store_path(&self.path) {
            return Err("invalid canonical Nix store path".into());
        }
        let hash = self
            .nar_hash
            .strip_prefix("sha256:")
            .ok_or("NAR hash must use sha256")?;
        if hash.len() != 52
            || !matches!(hash.as_bytes()[0], b'0' | b'1')
            || !hash.bytes().all(|b| NIX32.contains(&b))
        {
            return Err("NAR hash must be canonical sha256 Nix base32".into());
        }
        if self.nar_size == 0 || self.nar_size > MAX_NAR_BYTES {
            return Err("NAR size outside permitted bounds".into());
        }
        if self.references.len() > MAX_PATHS {
            return Err("too many references".into());
        }
        if self.references.iter().any(|p| !canonical_store_path(p))
            || self.references.windows(2).any(|w| w[0] >= w[1])
        {
            return Err("references must be sorted unique canonical store paths".into());
        }
        Ok(())
    }
    pub fn fingerprint(&self) -> String {
        format!(
            "1;{};{};{};{}",
            self.path,
            self.nar_hash,
            self.nar_size,
            self.references.join(",")
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub paths: Vec<ManifestPath>,
}
impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err("unsupported closure manifest version".into());
        }
        if self.paths.is_empty() || self.paths.len() > MAX_PATHS {
            return Err("closure requires 1..4096 paths".into());
        }
        let mut paths = BTreeSet::new();
        for path in &self.paths {
            path.validate()?;
            if !paths.insert(&path.path) {
                return Err("duplicate closure path".into());
            }
        }
        if serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > MAX_MANIFEST_BYTES {
            return Err("closure manifest exceeds 4 MiB".into());
        }
        Ok(())
    }
    pub fn parse_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err("closure manifest exceeds 4 MiB".into());
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        manifest.validate()?;
        Ok(manifest)
    }
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
        crate::SecretPath::parse(&self.identifier).map_err(|e| e.to_string())?;
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
            return Err("signing key must belong to declared host".into());
        }
        if !crate::artifact_signing::hex(&self.public_key_sha256, 64) {
            return Err("invalid signing public-key fingerprint".into());
        }
        self.manifest.validate()?;
        if serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > MAX_MANIFEST_BYTES {
            return Err("closure signing request exceeds 4 MiB".into());
        }
        Ok(())
    }
}

pub fn validate_public_key(value: &str) -> Result<(), String> {
    validate_named_base64(value, 32)
}
fn validate_named_base64(value: &str, size: usize) -> Result<(), String> {
    let (name, encoded) = value.split_once(':').ok_or("missing Nix key name")?;
    if name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    {
        return Err("invalid Nix key name".into());
    }
    if encoded.len() != size.div_ceil(3) * 4 {
        return Err("invalid Nix key encoded size".into());
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| "invalid Nix key base64")?;
    if decoded.len() != size || STANDARD.encode(&decoded) != encoded {
        return Err("invalid Nix key size or encoding".into());
    }
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathSignature {
    pub path: String,
    pub signature: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signatures {
    pub version: u32,
    pub signatures: Vec<PathSignature>,
}
impl Signatures {
    pub fn validate(&self, manifest: &Manifest) -> Result<(), String> {
        manifest.validate()?;
        if self.version != VERSION || self.signatures.len() != manifest.paths.len() {
            return Err("missing, extra or unsupported closure signatures".into());
        }
        let expected: BTreeSet<_> = manifest.paths.iter().map(|p| p.path.as_str()).collect();
        let mut seen = BTreeSet::new();
        for signature in &self.signatures {
            if !expected.contains(signature.path.as_str()) || !seen.insert(signature.path.as_str())
            {
                return Err("duplicate or unasked closure signature".into());
            }
            validate_named_base64(&signature.signature, 64)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(name: &str) -> String {
        format!("/nix/store/{}-{name}", "0".repeat(32))
    }
    fn entry() -> ManifestPath {
        ManifestPath {
            path: path("root"),
            nar_hash: format!("sha256:{}", "0".repeat(52)),
            nar_size: 7,
            references: vec![path("a"), path("b")],
        }
    }
    #[test]
    fn native_fingerprint_uses_commas_and_canonical_metadata() {
        let e = entry();
        e.validate().unwrap();
        assert_eq!(
            e.fingerprint(),
            format!(
                "1;{};{};7;{},{}",
                e.path, e.nar_hash, e.references[0], e.references[1]
            )
        );
        let mut e = e;
        e.references.clear();
        assert!(e.fingerprint().ends_with(';'));
    }
    #[test]
    fn rejects_adversarial_metadata() {
        for bad in [
            "/nix/store/../../root".to_string(),
            path("a/b"),
            path(".hidden"),
            path("a;evil"),
            path("a,evil"),
            format!("/nix/store/{}-name", "e".repeat(32)),
        ] {
            let mut e = entry();
            e.path = bad;
            assert!(e.validate().is_err());
        }
        let mut e = entry();
        e.references.reverse();
        assert!(e.validate().is_err());
        let mut e = entry();
        e.references.push(e.references[1].clone());
        assert!(e.validate().is_err());
        let mut e = entry();
        e.nar_hash = format!("sha256:2{}", "0".repeat(51));
        assert!(e.validate().is_err());
        for size in [0, MAX_NAR_BYTES + 1] {
            let mut e = entry();
            e.nar_size = size;
            assert!(e.validate().is_err());
        }
        let m = Manifest {
            version: VERSION,
            paths: vec![entry(), entry()],
        };
        assert!(m.validate().is_err());
        assert!(Manifest::parse_json(&vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
        assert!(Manifest::parse_json(br#"{"version":1,"paths":[],"extra":true}"#).is_err());
    }
    #[test]
    fn signatures_exactly_cover_manifest() {
        let m = Manifest {
            version: VERSION,
            paths: vec![entry()],
        };
        let mut s = Signatures {
            version: VERSION,
            signatures: vec![PathSignature {
                path: path("root"),
                signature: format!("cache:{}", STANDARD.encode([0u8; 64])),
            }],
        };
        s.validate(&m).unwrap();
        s.signatures[0].path = path("other");
        assert!(s.validate(&m).is_err());
        s.signatures[0].path = path("root");
        s.signatures[0].signature = format!("cache:{}", STANDARD.encode([0u8; 32]));
        assert!(s.validate(&m).is_err());
    }
}
