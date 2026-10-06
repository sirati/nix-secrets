# Storage Box SSH bootstrap

`storage-box-ssh-key` is an explicit generated-secret type. It turns a Storage
Box password that the operator manages into an SSH key local to the target. The
password is never installed on the target filesystem.

## Declaration

A generated leaf sits in the same canonical tree as an ordinary secret. The
leaf has `generatedSecret` in place of `destination`:

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

Use the Storage Box account's own SSH hostname and user, and port 23. Supply
complete pinned host-key lines. You can instead set `bootstrap.knownHostsFile`
to a managed public-info destination for that host and port. The
[Nix reference](nix/README.md) describes how to declare its pins.

## Deploy

1. Enter the Storage Box password at this leaf in the TUI. Its ciphertext is
   an input to the bootstrap task. It is not installed on the target as a file.
2. Deploy the target and approve the task. The target checks the pinned host
   key, generates an Ed25519 key locally, and adds its public half to the
   Storage Box's `.ssh/authorized_keys`.
3. After the remote update succeeds, the target publishes the private key at
   `output`. Consumers wait for that output through the normal readiness gate.

The comment on the managed authorized key starts with
`nix-secrets:<target-host>:<task-id>:`. An update replaces the entry with that
marker and keeps unrelated valid entries. Malformed or duplicate markers are
rejected. A retry reuses an installed key. A crash before local publication can
leave a key on the Storage Box. The retry then replaces the entry with the same
marker, so keys do not pile up.

## Security and recovery

During approval and authentication, the password reaches only the operator TUI
and the final target. The target never stores it, and the password never
appears in arguments or the environment. The generated private key never leaves
the target. Its persistent file is unencrypted so it can be used unattended.
`output.owner`, `group` and `mode` restrict access to it.

If a Storage Box host key changed or is not listed, the target refuses the
connection and the task fails. For a legitimate host-key rotation, review and update the pins before
you retry. If authentication, validation or the remote update fails, the target
publishes no new local key.

The target uses its OS random source and mixes in a contribution from the
operator, which it counts as zero entropy. The target erases the contribution
and the key seed after use. See [Threat model](THREAT-MODEL.md#generated-storage-box-credentials)
for the trust boundary and [Protocol](PROTOCOL.md#generated-secret-tasks)
for the task contract.
