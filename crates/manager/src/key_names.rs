//! Names keys the way the operator knows them.
//!
//! A key appears in the schema by recipient ID (a SHA-256 of the key) and
//! in the operator's ssh-agent by its comment, which is the item title in
//! 1Password ("IT Secrets"). Every place that names a key, whether a decrypt
//! recipient, the SSH login key or a signing key, shows the schema's name
//! (`recipientPublicKeys = { primary = …; }`), the agent's title and a short
//! fingerprint, matched by the public key itself, or says that the agent
//! does not hold it.
use nix_secrets_core::Schema;
use std::collections::BTreeMap;

/// The agent's keys by `algorithm base64`, with their comments.
#[derive(Clone, Debug, Default)]
pub struct AgentKeys {
    comments: BTreeMap<String, String>,
    /// Why the agent could not be asked, if it could not.
    error: Option<String>,
}

impl AgentKeys {
    /// Lists public key names from the selected agent and the standard
    /// 1Password socket. Listing keys never asks 1Password for approval.
    pub fn from_agent(socket: Option<&str>) -> Self {
        let primary = nix_secrets_transport::agent_keys(socket);
        let fallback = std::env::var_os("HOME")
            .map(|home| std::path::PathBuf::from(home).join(".1password/agent.sock"));
        let selected = socket
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("SSH_AUTH_SOCK").map(std::path::PathBuf::from));
        let fallback = fallback.filter(|path| {
            socket != Some("none") && path.exists() && selected.as_ref() != Some(path)
        });
        Self::from_agents(
            primary,
            fallback.map(|path| {
                nix_secrets_transport::agent_keys(Some(&path.to_string_lossy()))
            }),
        )
    }

    fn from_agents(
        primary: Result<Vec<String>, String>,
        fallback: Option<Result<Vec<String>, String>>,
    ) -> Self {
        let mut keys = match primary {
            Ok(lines) => Self::from_lines(&lines),
            Err(error) => Self {
                comments: BTreeMap::new(),
                error: Some(error),
            },
        };
        if let Some(Ok(lines)) = fallback {
            for (key, comment) in Self::from_lines(&lines).comments {
                let existing = keys.comments.entry(key).or_default();
                if existing.is_empty() {
                    *existing = comment;
                }
            }
            keys.error = None;
        }
        keys
    }

    pub fn from_lines(lines: &[String]) -> Self {
        let comments = lines
            .iter()
            .filter_map(|line| {
                let (key, comment) = split(line)?;
                Some((key, comment))
            })
            .collect();
        Self {
            comments,
            error: None,
        }
    }

    fn comment(&self, key: &str) -> Option<&str> {
        let (key, _) = split(key)?;
        self.comments.get(&key).map(String::as_str)
    }
}

/// `(algorithm base64, comment)` of an OpenSSH public key line.
fn split(line: &str) -> Option<(String, String)> {
    let mut fields = line.split_whitespace();
    let algorithm = fields.next()?;
    let encoded = fields.next()?;
    Some((
        format!("{algorithm} {encoded}"),
        fields.collect::<Vec<_>>().join(" "),
    ))
}

/// `SHA256:abcdefgh`, the first eight characters of the fingerprint.
pub fn short_fingerprint(key: &str) -> String {
    let encoded = key.split_whitespace().nth(1).unwrap_or("");
    let print = nix_secrets_transport::fingerprint(encoded);
    match print.strip_prefix("SHA256:") {
        Some(hash) => format!("SHA256:{}", hash.chars().take(8).collect::<String>()),
        None => print,
    }
}

/// The schema's name for a key: its `recipientPublicKeys` name on any host.
pub fn schema_name(schema: &Schema, key: &str) -> Option<String> {
    let (key, _) = split(key)?;
    schema.0.values().find_map(|host| {
        host.metadata
            .recipient_public_keys
            .iter()
            .find(|(_, public)| split(public).is_some_and(|(public, _)| public == key))
            .map(|(name, _)| name.clone())
    })
}

/// `"IT Secrets"`, or why the agent does not name the key.
pub fn agent_title(agent: &AgentKeys, key: &str) -> String {
    match (agent.comment(key), &agent.error) {
        (Some(comment), _) if !comment.is_empty() => format!("\"{comment}\""),
        (Some(_), _) => "in your ssh-agent".to_owned(),
        (None, Some(_)) => "ssh-agent unavailable".to_owned(),
        (None, None) => "not in your ssh-agent".to_owned(),
    }
}

/// `primary · "IT Secrets" (SHA256:abcdefgh)`, or with "not in your
/// ssh-agent" in place of the title.
pub fn describe(schema: &Schema, agent: &AgentKeys, key: &str) -> String {
    let name = schema_name(schema, key);
    let title = agent_title(agent, key);
    let print = short_fingerprint(key);
    match name {
        Some(name) => format!("{name} · {title} ({print})"),
        None => format!("{title} ({print})"),
    }
}

/// The public key of a recipient ID: the schema stores the ID as the
/// SHA-256 of `algorithm base64`.
pub fn recipient_key(schema: &Schema, id: &str) -> Option<String> {
    use sha2::Digest;
    let matches = |key: &String| {
        split(key).is_some_and(|(canonical, _)| {
            let digest = sha2::Sha256::digest(canonical.as_bytes());
            digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>() == id
        })
    };
    schema.0.values().find_map(|host| {
        host.metadata
            .recipient_public_keys
            .values()
            .find(|key| matches(key))
            .cloned()
            .or_else(|| find_leaf_key(&host.service_groups, id))
    })
}

fn find_leaf_key(
    groups: &BTreeMap<String, BTreeMap<String, nix_secrets_core::schema::SecretNode>>,
    id: &str,
) -> Option<String> {
    use nix_secrets_core::schema::SecretNode;
    fn walk(node: &SecretNode, id: &str) -> Option<String> {
        let (ids, keys) = match node {
            SecretNode::Secret(leaf) => (&leaf.recipient_ids, &leaf.recipient_public_keys),
            SecretNode::Generated(leaf) => (&leaf.recipient_ids, &leaf.recipient_public_keys),
            SecretNode::Operator(leaf) => (&leaf.recipient_ids, &leaf.recipient_public_keys),
            SecretNode::Branch(children) => {
                return children.values().find_map(|child| walk(child, id))
            }
        };
        ids.iter().zip(keys).find(|(each, _)| *each == id).map(|(_, key)| key.clone())
    }
    groups
        .values()
        .flat_map(BTreeMap::values)
        .find_map(|node| walk(node, id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

    fn schema() -> Schema {
        use sha2::Digest;
        let id = sha2::Sha256::digest(KEY.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Schema::from_json(
            &json!({"ns1": {
                "metadata": {"socketPath": "/run/nix-secrets/backend.sock",
                    "deployment": {"host": "ns1", "destination": "f@ns1", "port": 22},
                    "recipientPublicKeys": {"primary": KEY}},
                "services": {"app": {"token": {
                    "kind": "secret", "recipientPublicKeys": [KEY], "recipientIds": [id],
                    "recipientNames": ["primary"], "consumerUnits": [],
                    "destination": {"path": "/persistent/secrets/app/service/token",
                        "category": "service", "owner": "root", "group": "root", "mode": "0400"}}}}
            }})
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn a_recipient_is_named_by_schema_name_and_agent_title() {
        let schema = schema();
        let agent = AgentKeys::from_lines(&[format!("{KEY} IT Secrets")]);
        let text = describe(&schema, &agent, KEY);
        assert!(text.starts_with("primary · \"IT Secrets\" (SHA256:"), "{text}");
        let text = describe(&schema, &AgentKeys::from_lines(&[]), KEY);
        assert!(text.starts_with("primary · not in your ssh-agent (SHA256:"), "{text}");
    }

    #[test]
    fn onepassword_names_are_found_when_the_environment_agent_lacks_the_key() {
        for primary in [Ok(vec![]), Err("agent unavailable".into())] {
            let agent = AgentKeys::from_agents(primary, Some(Ok(vec![format!("{KEY} IT Secrets")])));
            assert_eq!(agent_title(&agent, KEY), "\"IT Secrets\"");
        }
    }

    #[test]
    fn fallback_preserves_existing_names_and_fills_empty_comments() {
        let fallback = Some(Ok(vec![format!("{KEY} IT Secrets")]));
        let named = AgentKeys::from_agents(Ok(vec![format!("{KEY} Existing name")]), fallback.clone());
        assert_eq!(agent_title(&named, KEY), "\"Existing name\"");
        let unnamed = AgentKeys::from_agents(Ok(vec![KEY.into()]), fallback);
        assert_eq!(agent_title(&unnamed, KEY), "\"IT Secrets\"");
        let absent = AgentKeys::from_agents(Ok(vec![]), Some(Err("missing socket".into())));
        assert_eq!(agent_title(&absent, KEY), "not in your ssh-agent");
    }

    #[test]
    fn a_recipient_id_resolves_to_its_key() {
        use sha2::Digest;
        let schema = schema();
        let id = sha2::Sha256::digest(KEY.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(recipient_key(&schema, &id).as_deref(), Some(KEY));
        assert_eq!(recipient_key(&schema, "0000"), None);
    }
}
