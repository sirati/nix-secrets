use nix::unistd::{chown, Group};
use nix_secrets_deploy::AuditDetail;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Serialize)]
pub struct Change<'a> {
    pub identifier: &'a str,
    pub action: &'static str,
    pub ssh_user: Option<String>,
    pub key_names: Vec<String>,
}

#[derive(Serialize)]
pub struct Event<'a> {
    pub host: &'a str,
    pub submitted_at: String,
    pub changes: Vec<Change<'a>>,
}

pub fn event<'a>(
    host: &'a str,
    identifiers: &'a [String],
    previous: &BTreeMap<String, String>,
    details: &BTreeMap<String, AuditDetail>,
) -> Result<String, String> {
    let changes = identifiers
        .iter()
        .map(|identifier| Change {
            identifier,
            action: if previous.contains_key(identifier) {
                "replaced"
            } else {
                "set"
            },
            ssh_user: details
                .get(identifier)
                .and_then(|detail| detail.ssh_user.clone()),
            key_names: details
                .get(identifier)
                .map_or_else(Vec::new, |detail| detail.key_names.clone()),
        })
        .collect();
    let submitted_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| e.to_string())?;
    serde_json::to_string(&Event {
        host,
        submitted_at,
        changes,
    })
    .map_err(|e| e.to_string())
}

pub fn write_event(path: &Path, group: &str, text: &str) -> Result<(), String> {
    if path.parent() != Some(Path::new("/run/nix-secrets/audit"))
        || path.extension().and_then(|part| part.to_str()) != Some("json")
        || !path
            .file_name()
            .and_then(|part| part.to_str())
            .is_some_and(|name| {
                name.len() <= 135
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
        || text.len() > 64 * 1024
    {
        return Err("invalid audit destination".into());
    }
    let group = Group::from_name(group)
        .map_err(|e| e.to_string())?
        .ok_or("audit group does not exist")?;
    let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    file.write_all(b"\n").map_err(|e| e.to_string())?;
    chown(&temporary, None, Some(group.gid)).map_err(|e| e.to_string())?;
    file.set_permissions(fs::Permissions::from_mode(0o640))
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&temporary, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinguishes_unset_from_replacement_without_values() {
        let identifiers = vec![
            "host.services.database.password".into(),
            "host.services.mail.token".into(),
        ];
        let previous =
            BTreeMap::from([("host.services.mail.token".into(), "opaque-version".into())]);
        let text = event("host", &identifiers, &previous, &BTreeMap::new()).unwrap();
        assert!(text.contains("\"action\":\"set\""));
        assert!(text.contains("\"action\":\"replaced\""));
        assert!(!text.contains("opaque-version"));
    }
}
