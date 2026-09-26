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
}

impl DerivedFrom {
    pub fn validate_definition(&self) -> Result<SecretPath, String> {
        let source = SecretPath::parse(&self.identifier)
            .map_err(|error| format!("derivedFrom.identifier is invalid: {error}"))?;
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

    /// The deployed bytes for a source value.
    pub fn frame(&self, source: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
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
