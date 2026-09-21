# Nix interface

Import `nixosModules.default`, enable `services.nixSecrets`, and describe each
secret as a leaf with a deployment destination. Configuration contains public
metadata only.

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
