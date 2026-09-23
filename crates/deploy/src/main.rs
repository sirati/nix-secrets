#![forbid(unsafe_code)]

use nix_secrets_deploy::{
    load_and_validate_manifest, load_target_state, run_generated_tasks, system_hostname, Deployer,
    DeploymentBatch, SecretDeployment,
};
use nix_secrets_transport::serve_deployment;
use std::io;
use std::path::Path;
mod audit;

fn main() {
    if let Err(error) = run() {
        eprintln!("secret-deploy: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os();
    let _program = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--manifest")) {
        return Err("usage: secret-deploy --manifest ABSOLUTE-NIX-STORE-JSON".into());
    }
    let manifest = args.next().ok_or("--manifest requires a path")?;
    let audit_file = match args.next().as_deref() {
        Some(value) if value == "--audit-file" => {
            Some(args.next().ok_or("--audit-file requires a path")?)
        }
        None => None,
        _ => return Err("unexpected receiver argument".into()),
    };
    let audit_group = if audit_file.is_some() {
        if args.next().as_deref() != Some(std::ffi::OsStr::new("--audit-group")) {
            return Err("--audit-group required with --audit-file".into());
        }
        Some(args.next().ok_or("--audit-group requires a name")?)
    } else {
        None
    };
    if args.next().is_some() {
        return Err("unexpected receiver argument".into());
    }
    let path = std::path::Path::new(&manifest);
    let hostname = system_hostname()?;
    let deployer = Deployer::persistent();
    let state = load_target_state(path, &hostname, &deployer.current_versions()?)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve_deployment(stdin.lock(), stdout.lock(), state, |mut batch| {
        let mut requested_identifiers = std::mem::take(&mut batch.requested_identifiers);
        requested_identifiers.extend(std::mem::take(&mut batch.requested_tasks));
        let wire_entries = std::mem::take(&mut batch.entries);
        let mut entries = wire_entries
            .into_iter()
            .map(|mut entry| SecretDeployment {
                identifier: std::mem::take(&mut entry.identifier),
                version_id: std::mem::take(&mut entry.version_id),
                contents_base64: std::mem::take(&mut entry.contents_base64),
            })
            .collect::<Vec<_>>();
        let generated = run_generated_tasks(path, &hostname, &batch.tasks)
            .map_err(|error| error.to_string())?;
        entries.extend(generated.deployments);
        let local = DeploymentBatch {
            version: u32::from(batch.version),
            requested_identifiers,
            entries,
        };
        let resolved = load_and_validate_manifest(path, &hostname, &local)
            .map_err(|error| error.to_string())?;
        let audit_details = resolved.audit_details();
        let previous = deployer
            .deploy_with_previous(&resolved)
            .map_err(|error| error.to_string())?;
        let audit = audit::event(
            &hostname,
            &local.requested_identifiers,
            &previous,
            &audit_details,
        )?;
        if let (Some(file), Some(group)) = (&audit_file, &audit_group) {
            audit::write_event(
                Path::new(file),
                group.to_str().ok_or("audit group is not UTF-8")?,
                &audit,
            )?;
        }
        eprintln!("nix-secrets-audit: {audit}");
        Ok((
            deployer
                .current_versions()
                .map_err(|error| error.to_string())?,
            generated.public_keys,
        ))
    })?;
    Ok(())
}
