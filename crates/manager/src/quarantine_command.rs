//! `nix-secrets quarantine`: the values hosts returned that the schema did
//! not accept, kept so nothing a host generated is lost.
//!
//! ```text
//! nix-secrets quarantine [--repository PATH] [--backend-socket PATH] list
//! nix-secrets quarantine [--repository PATH] [--backend-socket PATH] adopt ID
//! nix-secrets quarantine [--repository PATH] [--backend-socket PATH] discard ID
//! ```
//!
//! `adopt` checks the value against the current schema again and stores it
//! only where nothing is stored yet; it never replaces a stored value.
//! `discard` deletes the entry. Each acts on one entry, named by its id.
use crate::client::BackendClient;
use crate::controller::quarantine::describe;
use crate::with_secrets::{connect_backend, Options};
use nix_secrets_core::{
    GeneratedPublicKey, GeneratedSecretType, LeafSpec, QuarantinedContent, Schema, SecretPath,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "usage: nix-secrets quarantine [--repository PATH] [--backend-socket PATH] \
list | adopt ID | discard ID";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    List,
    Adopt(String),
    Discard(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub options: Options,
    pub action: Action,
}

pub fn parse(
    arguments: impl IntoIterator<Item = OsString>,
    working_directory: PathBuf,
) -> Result<Invocation, String> {
    let mut arguments = arguments.into_iter();
    let mut options = Options {
        repository: working_directory,
        ..Options::default()
    };
    let mut words = Vec::new();
    while let Some(argument) = arguments.next() {
        let text = argument
            .to_str()
            .ok_or_else(|| format!("unexpected argument {argument:?}; {USAGE}"))?
            .to_owned();
        let mut path = |name: &str| {
            arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| format!("{name} requires a path"))
        };
        match text.as_str() {
            "--repository" => options.repository = path("--repository")?,
            "--backend-socket" => options.backend_socket = Some(path("--backend-socket")?),
            _ if text.starts_with('-') => return Err(format!("unexpected argument {text:?}; {USAGE}")),
            _ => words.push(text),
        }
    }
    let action = match words.as_slice() {
        [list] if list == "list" => Action::List,
        [adopt, id] if adopt == "adopt" => Action::Adopt(id.clone()),
        [discard, id] if discard == "discard" => Action::Discard(id.clone()),
        _ => return Err(USAGE.into()),
    };
    Ok(Invocation { options, action })
}

pub fn run(invocation: &Invocation, runtime: &Path) -> Result<String, String> {
    let stream = connect_backend(&invocation.options, runtime)
        .map_err(|error| error.replace(" (or pass --local to decrypt here)", ""))?;
    let mut client = BackendClient::new(stream);
    match &invocation.action {
        Action::List => list(&mut client),
        Action::Adopt(id) => {
            let (json, _, _) = client.schema_document().map_err(|error| error.to_string())?;
            let schema = Schema::from_json(&json.ok_or("the backend has no evaluated schema")?)
                .map_err(|error| error.to_string())?;
            adopt(&mut client, &schema, id)
        }
        Action::Discard(id) => discard(&mut client, id),
    }
}

pub fn list(client: &mut BackendClient) -> Result<String, String> {
    let entries = client.list_quarantine().map_err(|error| error.to_string())?;
    if entries.is_empty() {
        return Ok("nothing is quarantined".into());
    }
    Ok(entries
        .iter()
        .map(|(id, value)| describe(id, value))
        .collect::<Vec<_>>()
        .join("\n"))
}

pub fn discard(client: &mut BackendClient, id: &str) -> Result<String, String> {
    if client.remove_quarantined(id).map_err(|error| error.to_string())? {
        Ok(format!("discarded {id}"))
    } else {
        Err(format!("nothing is quarantined as {id}"))
    }
}

/// Stores the entry as the value it claims to be, if the current schema
/// accepts it and nothing is stored there yet, then removes it from the
/// quarantine.
pub fn adopt(client: &mut BackendClient, schema: &Schema, id: &str) -> Result<String, String> {
    let entries = client.list_quarantine().map_err(|error| error.to_string())?;
    let value = entries
        .get(id)
        .ok_or_else(|| format!("nothing is quarantined as {id}"))?;
    let identifier = &value.identifier;
    let path = SecretPath::parse(identifier).map_err(|error| error.to_string())?;
    let refuse = |why: String| format!("cannot adopt {id} ({identifier}): {why}");
    match &value.content {
        QuarantinedContent::GeneratedRecord {
            format_version,
            version_id_base64,
            recipient_ids,
            age_ciphertext_base64,
            adopted,
        } => {
            let record = nix_secrets_transport::GeneratedRecord {
                format_version: *format_version,
                version_id_base64: version_id_base64.clone(),
                recipient_ids: recipient_ids.clone(),
                age_ciphertext_base64: age_ciphertext_base64.clone(),
                adopted: *adopted,
            };
            let envelope = crate::controller::unset::record_envelope(schema, identifier, &record)
                .map_err(refuse)?;
            if client.get(&path).map_err(|error| error.to_string())?.is_some() {
                return Err(refuse(
                    "a value is stored there; remove it first if this one should replace it".into(),
                ));
            }
            client
                .set_envelope_if_version(&path, envelope, None)
                .map_err(|error| refuse(error.to_string()))?;
        }
        QuarantinedContent::PublicKey { public_key } => {
            let Ok(LeafSpec::Generated(spec)) = schema.leaf(&path) else {
                return Err(refuse("it is not a generated key of the current schema".into()));
            };
            // A local key's public half arrives dated: `STAMP algorithm key`.
            let key = match public_key.split_ascii_whitespace().collect::<Vec<_>>().as_slice() {
                [_, algorithm, material] => format!("{algorithm} {material}"),
                _ => public_key.clone(),
            };
            match spec.generated_secret.secret_type {
                GeneratedSecretType::LocalSshKey => {
                    if client
                        .generated_public_key(&path)
                        .map_err(|error| error.to_string())?
                        .is_some()
                    {
                        return Err(refuse(
                            "a public key is stored there; discard this one or remove that first".into(),
                        ));
                    }
                    client
                        .set_generated_public_key_if_version(
                            &path,
                            GeneratedPublicKey {
                                version_id: format!("quarantine-{id}"),
                                public_key: key,
                            },
                            None,
                        )
                        .map_err(|error| refuse(error.to_string()))?;
                }
                GeneratedSecretType::StorageBoxSshKey => {
                    let stored = client
                        .get(&path)
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| refuse("its Storage Box input is not stored".into()))?;
                    if stored.public_key.is_some() {
                        return Err(refuse("a public key is attached there already".into()));
                    }
                    client
                        .set_public_key_if_version(&path, key, stored.version_id, None)
                        .map_err(|error| refuse(error.to_string()))?;
                }
            }
        }
    }
    client
        .remove_quarantined(id)
        .map_err(|error| format!("adopted {id}, but removing it from the quarantine failed: {error}"))?;
    Ok(format!("adopted {id} as {identifier}"))
}

