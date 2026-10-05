use nix::unistd::{chown, Group};
use nix_secrets_deploy::AuditDetail;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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
    if identifiers.is_empty() || identifiers.len() > 512 {
        return Err("invalid audit change count".into());
    }
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
    if !path.is_absolute()
        || path.extension().and_then(|part| part.to_str()) != Some("json")
        || !path
            .file_name()
            .and_then(|part| part.to_str())
            .is_some_and(|name| {
                !name.starts_with('.')
                    && name.len() <= 135
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
    let parent = path.parent().ok_or("audit parent missing")?;
    let mut ancestor = std::path::PathBuf::new();
    for component in parent.components() {
        if matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        ) {
            return Err("invalid audit ancestry".into());
        }
        ancestor.push(component);
        let meta = fs::symlink_metadata(&ancestor).map_err(|_| "inspect audit ancestry")?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err("unsafe audit ancestry".into());
        }
    }
    let parent_meta = fs::symlink_metadata(parent).map_err(|_| "inspect audit parent")?;
    if parent_meta.gid() != group.gid.as_raw() || parent_meta.mode() & 0o7777 != 0o750 {
        return Err("audit parent group or mode mismatch".into());
    }
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "audit staging randomness unavailable")?;
    let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let temporary = parent.join(format!(".audit-{suffix}"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| "create audit staging file")?;
        file.write_all(text.as_bytes()).map_err(|_| "write audit")?;
        file.write_all(b"\n").map_err(|_| "write audit newline")?;
        chown(&temporary, None, Some(group.gid)).map_err(|_| "set audit group")?;
        file.set_permissions(fs::Permissions::from_mode(0o640))
            .map_err(|_| "protect audit")?;
        file.sync_all().map_err(|_| "sync audit")?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &temporary,
            rustix::fs::CWD,
            path,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| "publish audit without replacement")?;
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| "sync audit directory".to_owned())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unbounded_audit_and_unsafe_destination_before_writing() {
        assert!(event("host", &[], &BTreeMap::new(), &BTreeMap::new()).is_err());
        let oversized = vec!["host.services.secret".into(); 513];
        assert!(event("host", &oversized, &BTreeMap::new(), &BTreeMap::new()).is_err());
        for path in [
            "relative.json",
            "/run/nix-secrets/audit/.hidden.json",
            "/run/nix-secrets/audit/test.service",
        ] {
            assert!(write_event(Path::new(path), "root", "{}").is_err());
        }
    }
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
