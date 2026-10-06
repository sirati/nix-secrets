# Storage Box SSH bootstrap

A `storage-box-ssh-key` leaf turns a Storage Box password that the operator
stores into an SSH key generated on the target. The password is never written
to the target.

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

The port must be 23. Set either `hostPublicKeys` or `knownHostsFile`, which
names a [public-info](nix/README.md#public-information) destination.

Enter the password at this leaf, then deploy the target. The target connects
with the password, rejects host keys that are not pinned, and generates an
Ed25519 key. It adds the public key to the Storage Box's
`.ssh/authorized_keys` with a comment starting
`nix-secrets:<target-host>:<task-id>:`. It keeps other entries and replaces an
existing entry with that marker. Only after that succeeds does it publish the
private key at `output`. A retry reuses an installed key, and a crash leaves
at most one marked entry.

The private key is stored unencrypted on the target so that services can use
it unattended. See the [threat model](THREAT-MODEL.md#storage-box-keys) and the
[protocol](PROTOCOL.md#storage-box-tasks).
