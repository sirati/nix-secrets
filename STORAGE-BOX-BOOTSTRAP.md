# Storage Box SSH bootstrap

`storage-box-ssh-key` is an explicit generated-secret type. It converts an
operator-managed Storage Box password into a target-local SSH key without ever
installing the password on the target filesystem.

## Declaration

A generated leaf occupies the same canonical tree as an ordinary secret. The
leaf has `generatedSecret` instead of `destination`:

```nix
services.nixSecrets.services.backup.secrets.storageBoxKey = {
  recipientPublicKeys = [ operatorAgeSshPublicKey ];
  consumerUnits = [ "borgbackup-job-files.service" ];
  generatedSecret = {
    type = "storage-box-ssh-key";
    output = {
      path = "/persistent/secrets/backup/backup/storage-box-key";
      category = "backup";
      owner = "backup";
      group = "backup";
      mode = "0400";
    };
    bootstrap = {
      host = "u000000.your-storagebox.de";
      port = 23;
      user = "u000000-sub1";
      hostPublicKeys = [ "ssh-ed25519 AAAA..." ];
    };
  };
};
```

Use the Storage Box account's own SSH hostname, user and port 23. Supply
complete pinned host-key lines. Alternatively, set `bootstrap.knownHostsFile`
to a managed public-info destination for that host and port; declare its pins
as described in the [Nix reference](nix/README.md).

## Deploy

1. Enter the Storage Box password at this leaf in the TUI. Its ciphertext is
   a bootstrap input, not a file to install on the target.
2. Deploy the target and approve the task. The target checks the pinned host
   key, generates an Ed25519 key locally, and installs its public half in the
   Storage Box's `.ssh/authorized_keys`.
3. After the remote update succeeds, the target publishes the private key at
   `output`. Consumers wait for that output through the normal readiness gate.

The managed authorized-key comment starts with
`nix-secrets:<target-host>:<task-id>:`. Updates replace that marker and preserve
unrelated valid entries; malformed or duplicate markers are rejected.
Retries reuse an installed key. A crash before local publication can leave a
remote key, but retry replaces the same marker rather than accumulating keys.

## Security and recovery

The password reaches only the operator TUI and final target during approval
and authentication; it is never persisted on the target or passed in arguments
or the environment. The generated private key never leaves the target.
Its persistent file is unencrypted for unattended use, with access restricted
by `output.owner`, `group` and `mode`.

Changed or unlisted Storage Box host keys fail closed. Review and update the
pins before retrying a legitimate host-key rotation. Authentication, validation
or remote-update failure publishes no new local key.

The target uses its OS random source, mixed with an operator contribution
without claiming entropy credit. The contribution and key seed are erased
after use. See [Threat model](THREAT-MODEL.md#generated-storage-box-credentials)
for the trust boundary and [Protocol](PROTOCOL.md#generated-secret-tasks)
for the task contract.
