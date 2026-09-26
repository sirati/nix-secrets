#![forbid(unsafe_code)]

use nix_secrets_crypto::AgeCommandProvider;
use nix_secrets_deploy::{
    install_public_default, load_and_validate_manifest, load_target_state, run_generated_tasks,
    run_value_generation, system_hostname, Deployer, DeploymentBatch, SecretDeployment, SystemHost,
};
use nix_secrets_transport::{serve_deployment, AppliedOutput};
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
    let first = args.next();
    if first.as_deref() == Some(std::ffi::OsStr::new("--install-public-default")) {
        let manifest_flag = args.next();
        let manifest = args.next();
        let identifier_flag = args.next();
        let identifier = args.next();
        let source_flag = args.next();
        let source = args.next();
        let version_flag = args.next();
        let version = args.next();
        if manifest_flag.as_deref() != Some(std::ffi::OsStr::new("--manifest"))
            || identifier_flag.as_deref() != Some(std::ffi::OsStr::new("--identifier"))
            || source_flag.as_deref() != Some(std::ffi::OsStr::new("--source"))
            || version_flag.as_deref() != Some(std::ffi::OsStr::new("--version"))
            || args.next().is_some()
        {
            return Err("invalid public default invocation".into());
        }
        let identifier = identifier.ok_or("missing identifier")?;
        let version = version.ok_or("missing version")?;
        return install_public_default(
            Path::new(&manifest.ok_or("missing manifest")?),
            &system_hostname()?,
            identifier.to_str().ok_or("identifier is not UTF-8")?,
            Path::new(&source.ok_or("missing source")?),
            version.to_str().ok_or("version is not UTF-8")?,
        )
        .map_err(Into::into);
    }
    if first.as_deref() != Some(std::ffi::OsStr::new("--manifest")) {
        return Err(
            "usage: secret-deploy --manifest ABSOLUTE-NIX-STORE-JSON [--age PATH] [--audit-file PATH --audit-group NAME]"
                .into(),
        );
    }
    let manifest = args.next().ok_or("--manifest requires a path")?;
    let mut next = args.next();
    // The age program encrypts values generated here to their recipients.
    let age = if next.as_deref() == Some(std::ffi::OsStr::new("--age")) {
        let program = args.next().ok_or("--age requires a path")?;
        next = args.next();
        program
    } else {
        std::ffi::OsString::from("age")
    };
    let audit_file = match next.as_deref() {
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
    let public_deployer = Deployer::public_info();
    let mut current = deployer.current_versions()?;
    current.extend(public_deployer.current_versions()?);
    let state = load_target_state(path, &hostname, &current)?;
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
        let values = run_value_generation(
            path,
            &hostname,
            &batch.generate,
            &batch.derive,
            &current,
            &AgeCommandProvider::new(age.clone()),
            &mut SystemHost,
        )
        .map_err(|error| error.to_string())?;
        entries.extend(values.deployments);
        let local = DeploymentBatch {
            version: u32::from(batch.version),
            requested_identifiers,
            entries,
        };
        let resolved = load_and_validate_manifest(path, &hostname, &local)
            .map_err(|error| error.to_string())?;
        let audit_details = resolved.audit_details();
        let (secrets, public) = resolved.partition();
        let mut previous = std::collections::BTreeMap::new();
        if !public.is_empty() {
            previous.extend(
                public_deployer
                    .deploy_with_previous(&public)
                    .map_err(|error| error.to_string())?,
            );
        }
        if !secrets.is_empty() {
            previous.extend(
                deployer
                    .deploy_with_previous(&secrets)
                    .map_err(|error| error.to_string())?,
            );
        }
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
        let mut versions = deployer
            .current_versions()
            .map_err(|error| error.to_string())?;
        versions.extend(
            public_deployer
                .current_versions()
                .map_err(|error| error.to_string())?,
        );
        Ok(AppliedOutput {
            versions,
            generated_public_keys: generated.public_keys,
            generated_records: values.records,
        })
    })?;
    Ok(())
}
