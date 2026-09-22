# Nix interface

Import `nixosModules.default`, enable `services.nixSecrets`, and describe each
secret as a leaf with a deployment destination. Configuration contains public
metadata only. Optional value-generation policies and their limits are in
[`GENERATION-POLICIES.md`](../GENERATION-POLICIES.md).

```nix
{
  services.nixSecrets = {
    enable = true;
    defaultRecipientPublicKeys = [ "ssh-ed25519 AAAA... workstation" ];
    services.mail = {
      consumerUnits = [ "stalwart-mail.service" ];
      secrets = {
        database-password.destination = {
          path = "/persistent/secrets/mail/service/database-password";
          category = "service";
          owner = "stalwart-mail";
          group = "stalwart-mail";
          mode = "0400";
        };
        backup = {
          _recipientPublicKeys = [ "ssh-ed25519 AAAA... backup-operator" ];
          passphrase.destination = {
            path = "/persistent/secrets/mail/backup/passphrase";
            category = "backup";
            owner = "mail-backup";
            group = "mail-backup";
            mode = "0400";
          };
        };
      };
    };
  };
}
```

A generated Storage Box key leaf consumes an operator-encrypted bootstrap
password and publishes only its locally generated private key at `output`:

```nix
services.nixSecrets.services.backup.secrets.storage-key.generatedSecret = {
  type = "storage-box-ssh-key";
  output = {
    path = "/persistent/secrets/backup/backup/storage-key";
    category = "backup";
    owner = "backup";
    group = "backup";
    mode = "0400";
  };
  bootstrap = {
    host = "u123.storagebox.example";
    port = 23;
    user = "u123";
    hostPublicKeys = [ "ssh-ed25519 AAAA... pinned-storage-box-host" ];
  };
};
```

The normalized leaf has `kind = "generated"`. Ordinary destination leaves have
`kind = "secret"`. Generated outputs take part in destination uniqueness and
service readiness checks. Host keys are complete, pinned OpenSSH public-key
lines; duplicate pins and ports other than the Storage Box SSH port 23 fail
schema validation.

`defaultRecipientPublicKeys` is inherited by every leaf. A service can set
`recipientPublicKeys`, a subtree can set `_recipientPublicKeys`, and a leaf can
set `recipientPublicKeys`.

The normalized public inventory is available as
`config.services.nixSecrets.evaluated`. Its outer shape is
`<hostname>.services.<service>` and
`<hostname>.user-<user>-services.<service>`. A JSON store artifact is available
at `config.system.build.nixSecretsManifest`.

Enable `services.secretsReadyWaiter` to derive readiness gates from the same
tree. It creates one waiter per service. Only units named by `consumerUnits`
receive `Requires=` and `After=` edges. It does not add a dependency to
`multi-user.target` or SSH.
