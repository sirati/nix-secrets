//! Values derived from another stored secret: `prefix + source + suffix`.
//!
//! A derived value is never stored. At deployment the operator decrypts the
//! source, frames it, and deploys the result like any other value, so it
//! always matches its source, also across hosts.

use serde::{Deserialize, Serialize};

use super::{LeafSpec, Schema, SchemaError, SecretKind, SecretPath};

pub const MAX_DERIVED_AFFIX_BYTES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedFrom {
    /// Canonical identifier of the source, which may be on another host.
    pub identifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub suffix: String,
    /// Selects one string field of a TOML source instead of the whole
    /// value, e.g. `["tsig", "secret_base64"]`.
    #[serde(rename = "tomlPath", default, skip_serializing_if = "Vec::is_empty")]
    pub toml_path: Vec<String>,
    /// Escape a PostgreSQL password-file field before adding its framing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

impl DerivedFrom {
    pub fn validate_definition(&self) -> Result<SecretPath, String> {
        let source = SecretPath::parse(&self.identifier)
            .map_err(|error| format!("derivedFrom.identifier is invalid: {error}"))?;
        if self.toml_path.len() > 8
            || self
                .toml_path
                .iter()
                .any(|key| key.is_empty() || key.len() > 128 || key.contains('\0'))
        {
            return Err("derivedFrom.tomlPath must be at most 8 non-empty keys".into());
        }
        if self
            .encoding
            .as_deref()
            .is_some_and(|value| value != "pgpass")
        {
            return Err("derivedFrom.encoding must be pgpass when set".into());
        }
        for affix in [&self.prefix, &self.suffix] {
            if affix.len() > MAX_DERIVED_AFFIX_BYTES || affix.contains('\0') {
                return Err(format!(
                    "derivedFrom prefix and suffix must be at most {MAX_DERIVED_AFFIX_BYTES} bytes without NUL"
                ));
            }
        }
        Ok(source)
    }

    /// The deployed version: `d-` and 32 hex digits of SHA-256 over the
    /// length-prefixed source version, source identifier, prefix and suffix.
    /// Operator and target compute it alike, so a value derived on either
    /// side has the same version and is replaced exactly when its source or
    /// framing changes.
    pub fn version(&self, source_version: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for part in [
            source_version,
            self.identifier.as_bytes(),
            self.prefix.as_bytes(),
            self.suffix.as_bytes(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        // Without a selector the version is unchanged from before it existed.
        if !self.toml_path.is_empty() {
            let path = self.toml_path.join("\0");
            hasher.update((path.len() as u64).to_be_bytes());
            hasher.update(path.as_bytes());
        }
        if let Some(encoding) = &self.encoding {
            let tag = format!("encoding:{encoding}");
            hasher.update((tag.len() as u64).to_be_bytes());
            hasher.update(tag.as_bytes());
        }
        let digest = hasher.finalize();
        let hex = digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("d-{hex}")
    }

    /// Canonical description compared between operator and target.
    pub fn fingerprint(&self) -> String {
        serde_json::to_string(self).expect("derivations serialize")
    }

    /// The deployed bytes for a source value, or why the source does not
    /// hold the selected field.
    pub fn frame(&self, source: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        if self.toml_path.is_empty() {
            return self.frame_encoded(source);
        }
        let field = self.select(source)?;
        self.frame_encoded(field.as_bytes())
    }

    fn frame_encoded(&self, source: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        match self.encoding.as_deref() {
            None => Ok(self.frame_bytes(source)),
            Some("pgpass") => {
                if source.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
                    return Err(
                        "pgpass source must be one password without NUL or line breaks".into(),
                    );
                }
                let mut escaped = zeroize::Zeroizing::new(Vec::with_capacity(source.len()));
                for byte in source {
                    if matches!(byte, b':' | b'\\') {
                        escaped.push(b'\\');
                    }
                    escaped.push(*byte);
                }
                Ok(self.frame_bytes(&escaped))
            }
            Some(_) => Err("derivedFrom.encoding must be pgpass when set".into()),
        }
    }

    /// The string at `toml_path` in a TOML source.
    fn select(&self, source: &[u8]) -> Result<zeroize::Zeroizing<String>, String> {
        let path = self.toml_path.join(".");
        let text = std::str::from_utf8(source)
            .map_err(|_| format!("{} is not UTF-8 TOML, so it has no {path}", self.identifier))?;
        let document: toml::Table = toml::from_str(text)
            .map_err(|_| format!("{} is not valid TOML, so it has no {path}", self.identifier))?;
        let mut value: Option<&toml::Value> = None;
        let mut table = &document;
        for (index, key) in self.toml_path.iter().enumerate() {
            let next = table
                .get(key)
                .ok_or_else(|| format!("{} has no field {path}", self.identifier))?;
            if index + 1 == self.toml_path.len() {
                value = Some(next);
            } else {
                table = next
                    .as_table()
                    .ok_or_else(|| format!("{} has no field {path}", self.identifier))?;
            }
        }
        value
            .and_then(toml::Value::as_str)
            .map(|text| zeroize::Zeroizing::new(text.to_owned()))
            .ok_or_else(|| format!("{}: {path} is not a string", self.identifier))
    }

    fn frame_bytes(&self, source: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
        let mut output = zeroize::Zeroizing::new(Vec::with_capacity(
            self.prefix.len() + source.len() + self.suffix.len(),
        ));
        output.extend_from_slice(self.prefix.as_bytes());
        output.extend_from_slice(source);
        output.extend_from_slice(self.suffix.as_bytes());
        output
    }
}

impl Schema {
    /// Checks every derived leaf whose source host is part of this schema. A
    /// target manifest holds only its own host, so a cross-host source is
    /// checked where the full inventory is evaluated.
    pub(super) fn validate_derived(&self) -> Result<(), SchemaError> {
        for (path, spec) in self.stored_leaves()? {
            let Some(derived) = &spec.derived_from else {
                continue;
            };
            let source = derived
                .validate_definition()
                .map_err(|message| SchemaError::InvalidValueDefinition(path.clone(), message))?;
            if !self.0.contains_key(&source.components()[0]) {
                continue;
            }
            let fail = |message: &str| {
                SchemaError::InvalidValueDefinition(path.clone(), message.to_owned())
            };
            if source == path {
                return Err(fail("a value cannot be derived from itself"));
            }
            match self.leaf(&source) {
                Ok(LeafSpec::Stored(source))
                    if matches!(source.kind, SecretKind::Secret)
                        && source.derived_from.is_none() => {}
                Ok(_) => {
                    return Err(fail(
                        "derivedFrom must name a stored secret that is not itself derived",
                    ));
                }
                Err(_) => return Err(fail("derivedFrom names a value absent from the schema")),
            }
        }
        Ok(())
    }

    fn stored_leaves(&self) -> Result<Vec<(SecretPath, super::SecretSpec)>, SchemaError> {
        let mut leaves = Vec::new();
        for (host, entry) in &self.0 {
            for (namespace, services) in &entry.service_groups {
                for (service, node) in services {
                    collect(
                        self,
                        node,
                        &mut vec![host.clone(), namespace.clone(), service.clone()],
                        &mut leaves,
                    )?;
                }
            }
        }
        Ok(leaves)
    }
}

fn collect(
    schema: &Schema,
    node: &super::SecretNode,
    path: &mut Vec<String>,
    leaves: &mut Vec<(SecretPath, super::SecretSpec)>,
) -> Result<(), SchemaError> {
    match node {
        super::SecretNode::Branch(children) => {
            for (name, child) in children {
                path.push(name.clone());
                collect(schema, child, path, leaves)?;
                path.pop();
            }
        }
        super::SecretNode::Secret(_) => {
            let secret_path = SecretPath::new(path.clone())?;
            if let LeafSpec::Stored(spec) = schema.leaf(&secret_path)? {
                leaves.push((secret_path, spec));
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod toml_tests {
    use super::*;

    fn knot() -> DerivedFrom {
        DerivedFrom {
            identifier: "ns1.services.dyndns-rfc2136.credentials".into(),
            prefix: "key:\n  - id: dyndns-rfc2136\n    algorithm: hmac-sha256\n    secret: ".into(),
            suffix: "\n".into(),
            toml_path: vec!["tsig".into(), "secret_base64".into()],
            encoding: None,
        }
    }

    const CREDENTIALS: &str = "[tsig]\nkey_name = \"dyndns-rfc2136\"\nsecret_base64 = \"c2VjcmV0\"\nalgorithm = \"hmac-sha256\"\n\n[[credentials]]\nusername = \"router\"\npassword = \"pw\"\n";

    #[test]
    fn frames_one_field_of_a_toml_source() {
        let framed = knot().frame(CREDENTIALS.as_bytes()).unwrap();
        assert!(framed.ends_with(b"secret: c2VjcmV0\n"));
        assert!(!String::from_utf8_lossy(&framed).contains("password"));
    }

    #[test]
    fn a_missing_or_non_string_field_is_named() {
        let error = knot().frame(b"[tsig]\nkey_name = \"x\"\n").unwrap_err();
        assert!(error.contains("has no field tsig.secret_base64"), "{error}");
        let error = knot().frame(b"[tsig]\nsecret_base64 = 3\n").unwrap_err();
        assert!(
            error.contains("tsig.secret_base64 is not a string"),
            "{error}"
        );
        let error = knot().frame(b"not = [toml").unwrap_err();
        assert!(error.contains("is not valid TOML"), "{error}");
    }

    #[test]
    fn the_selector_is_part_of_the_version_only_when_set() {
        let mut plain = knot();
        plain.toml_path.clear();
        assert_ne!(knot().version(b"v"), plain.version(b"v"));
        assert!(knot().validate_definition().is_ok());
        let mut deep = knot();
        deep.toml_path = vec!["".into()];
        assert!(deep.validate_definition().is_err());
    }
}

#[cfg(test)]
mod pgpass_tests {
    use super::*;
    fn field() -> DerivedFrom {
        DerivedFrom {
            identifier: "db.services.postgresql.password".into(),
            prefix: "host:5432:replication:replicator:".into(),
            suffix: "\n".into(),
            toml_path: vec![],
            encoding: Some("pgpass".into()),
        }
    }
    #[test]
    fn escapes_password_delimiters_and_backslashes() {
        assert_eq!(
            &*field().frame(br"pass:word\tail").unwrap(),
            br"host:5432:replication:replicator:pass\:word\\tail
"
        );
    }
    #[test]
    fn rejects_record_injection_without_disclosing_the_password() {
        for source in [b"secret\nother".as_slice(), b"secret\r", b"secret\0"] {
            let error = field().frame(source).unwrap_err();
            assert!(!error.contains("secret"));
        }
    }
    #[test]
    fn encoding_changes_the_deployed_version() {
        let encoded = field();
        let mut plain = encoded.clone();
        plain.encoding = None;
        assert_ne!(encoded.version(b"v"), plain.version(b"v"));
        assert_ne!(encoded.fingerprint(), plain.fingerprint());
        plain.encoding = Some("unknown".into());
        assert!(plain.validate_definition().is_err());
    }
}
