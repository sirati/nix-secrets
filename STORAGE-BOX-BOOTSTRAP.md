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

The complete normalized leaf is public Nix-store metadata. It contains the
canonical identifier, recipient IDs, output metadata, Storage Box address and
complete pinned OpenSSH host public-key lines. It never contains the password
or a private key.

The ciphertext at that identifier in `nix-secrets.toml` is the bootstrap
password. It is a task input, not a deployable file. The generated private key
is the output used by readiness checks and consumers.

## Execution

1. The frontend and target independently resolve the selected identifier from
   freshly evaluated/generated manifests and compare every public field.
2. The frontend asks for task approval, decrypts the password locally and
   obtains exactly 32 bytes from the operating-system CSPRNG.
3. The password and contribution travel only in the already authenticated,
   host-key-verified end-to-end deployment SSH stream.
4. The target writes the full contribution to `/dev/urandom` using ordinary
   safe Rust I/O. This mixes untrusted input into the Linux random pool without
   using `RNDADDENTROPY` or claiming entropy credit. It then erases the input.
5. After that write succeeds, the target obtains fresh target-local OS random
   bytes and generates an Ed25519 key. If an output key already exists, it is
   parsed and reused; retries never rotate implicitly.
6. The target password-authenticates to the configured Storage Box, accepting
   only a complete configured host key. It reads `.ssh/authorized_keys`,
   preserves unrelated valid lines, and replaces the single line whose comment
   starts with `nix-secrets:<target-host>:<task-id>:`. The new comment also
   includes the UTC date.
7. The remote file is uploaded and renamed atomically. Only after that succeeds
   does the target atomically publish the private key at the declared output
   path. A crash before local publication can leave the remote replacement;
   retry replaces the same marker rather than adding another active key.

Malformed or duplicate task markers are rejected. An incorrect host key,
password failure, schema mismatch, malformed contribution, remote update
failure, or local publication failure produces no newly published local key.
The password, contribution and private seed are zeroized on all ordinary Rust
return paths.

## Boundary and limitations

The frontend process necessarily sees the decrypted password during an
approved run. The final target necessarily sees it while authenticating the
bootstrap connection. The repository backend and byte relays see only age
ciphertext or encrypted SSH traffic.

The password is never supplied in an argument or environment variable. The
implementation uses in-process SSH/SFTP, so it does not need an askpass helper,
temporary password file or shell command. The target private key is generated
and serialized in memory and never leaves the target. Its only filesystem
publication is the declared persistent output.

Pinned host keys are availability-sensitive: Storage Box host-key rotation
requires an operator-reviewed Nix configuration change before bootstrap can
continue. The generated key is intentionally unencrypted because unattended
backup services must use it. The declared file owner and mode restrict local
access.
