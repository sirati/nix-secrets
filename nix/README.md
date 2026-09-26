# Nix interface

Import `nixosModules.default`, enable `services.nixSecrets`, and describe each
secret as a leaf with a deployment destination. Configuration contains public
metadata only. A password leaf may declare `valueType = "password"` and optional
consumer format limits. The TUI offers password and passphrase generation as
an operator choice.
Use `valueType = "key"` for private keys shown in the key-only view. An optional
`description` on any leaf is shown when it is selected. Set
`humanFacing = true` for values people enter or use directly; the TUI can
restrict its view to these leaves. Generated password/passphrase choices are
available for every password leaf, and consumer constraints describe only the
receiving program's format limits. Set
`externalInputRequired = true` only when a value must be supplied from a
separately administered system, such as a password set in a hosting provider's
control panel. The TUI's **Required** view shows only leaves with this flag.
It does not infer this property from password type, generator availability, or
whether the value is currently set. The default is `false`.
Each normalized leaf also has a semantic `identity` with `host`, `scope`,
`user`, `service`, `responsibility`, `namespace`, and `name`. The first three
come from the enclosing host and system/user service declaration. A leaf may
override the other four:

```nix
identity = {
  service = "mail";
  responsibility = "backup";
  namespace = "shared"; # omit for a value without a namespace
  name = "passphrase";
};
presentation = {
  explanation = "Passphrase for the mail backup repository";
  facing = "generated"; # external, human, or another label
  type = "passphrase"; # private-key, public-key, or another label
};
```

The identity is unique across the evaluated inventory. `presentation` is
optional and defaults from the existing description, facing flags, and value
type. The dotted identifier from the existing Nix declaration remains the
stable storage and deployment key, so changing the semantic identity or tree
ordering does not rewrite encrypted TOML entries or target paths. Keep an
existing declaration at its current path when adding these attributes.
In the TUI, `F` opens attribute filters; `T` chooses and orders tree attributes;
`P` shows all attributes of the selected value. Any attribute can be filtered
whether it is in the tree or filter-only.
Set
`destination.contentType = "openssh-private-key"` or `"openssh-public-key"`
when the consumer requires that format; the frontend and target both reject
malformed key material. `named-ssh-ed25519-public-keys` remains available for
the authorized-key inventory.
Set `services.<name>.displayPath = [ "mail" "backup" ];` to group a service in
the TUI. This changes presentation only: the service name remains the secret
identifier and keeps its own readiness gate and consumer units. The same option
is available on `userServices.<user>.<name>`.
For a stored OpenSSH private key, the TUI derives its public half when setting
the value and saves that public key beside the ciphertext in TOML. The `p`
hotkey copies the public key without decrypting the private key. Target-generated
keys save their returned public metadata after a compare-and-set and read-back.

```nix
{
  services.nixSecrets = {
    enable = true;
    defaultRecipientPublicKeys = [ "ssh-ed25519 AAAA... workstation" ];
    services.mail = {
      consumerUnits = [ "stalwart-mail.service" ];
      secrets = {
        database-password = {
          valueType = "password";
          destination = {
            path = "/persistent/secrets/mail/service/database-password";
            category = "service";
            owner = "stalwart-mail";
            group = "stalwart-mail";
            mode = "0400";
          };
        };
        backup = {
          _recipientPublicKeys = [ "ssh-ed25519 AAAA... backup-operator" ];
          passphrase = {
            valueType = "password";
            destination = {
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
  };
}
```

Unset password leaves, and leaves declaring `valueGenerator`, are generated
on the target during deployment unless they set `externalInputRequired = true`
or `generateOnDeploy = false`. See "Values generated at deployment" in the top
level README for the `valueGenerator` format.

`kind = "operator"` declares an operator-only value with an optional
`generator = { installable; args; }`; it is never deployed. `lib.operatorPublicKey
STORE IDENTIFIER` returns its stored public key as base64, or null. See
"Operator-only secrets" in the top level README.

Only consumer compatibility limits belong in `consumerConstraints`. For example,
if a program rejects values longer than 64 characters, declare
`consumerConstraints.cannotHandleLongerThan = 64;`. The optional fields are
`cannotHandleShorterThan`, `cannotHandleLongerThan`, and `matchingRegex`.
They are enforced for typed passwords entered, pasted, or generated in the TUI.

A generated Storage Box key leaf consumes an operator-encrypted bootstrap
password and publishes only its locally generated private key at `output`:

```nix
services.nixSecrets.services.backup.secrets.storage-key = {
  valueType = "password";
  generatedSecret = {
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
};
```

The normalized leaf has `kind = "generated"`. Ordinary destination leaves have
`kind = "secret"`. Generated outputs take part in destination uniqueness and
service readiness checks. Host keys are complete, pinned OpenSSH public-key
lines; duplicate pins and ports other than the Storage Box SSH port 23 fail
schema validation.
For a host key maintained as public information, use
`bootstrap.knownHostsFile = "/persistent/public-info/storage-box/known-hosts"`
instead of `hostPublicKeys`. The target requires that path to be an attested
public-info destination for the same host and port, then reads and validates
the current file before connecting. It never fetches or accepts a host key on
its own.

To name recipients once, use
`recipientPublicKeys = { primary = "ssh-ed25519 ..."; };` and
`defaultRecipientNames = [ "primary" ];` at `services.nixSecrets`. A service
can set `recipientNames`, a subtree `_recipientNames`, and a leaf
`recipientNames`. Existing `defaultRecipientPublicKeys`, service
`recipientPublicKeys`, subtree `_recipientPublicKeys`, and leaf
`recipientPublicKeys` lists remain supported. New TOML records refer to a
versioned recipient name; the top-level registry retains older identities
after rotation.

Public information uses a leaf with `kind = "public-info"`,
`sharedPublicId = "storage-box/known-hosts"`, `expectedSshHost`, and
`expectedSshPort`. Its destination is the corresponding
`/persistent/public-info/storage-box/known-hosts`, owned by root with mode
`0644` and `contentType = "ssh-known-hosts"`. The value is one exact Ed25519
`[host]:port` known-hosts line, stored in plaintext under
`[public_info."storage-box/known-hosts"]` in `nix-secrets.toml`. The same value
can be deployed to multiple hosts; each target checks the host, port, key
format, and destination again. Public-info leaves never create a
secrets-readiness waiter.

Set `installDefaultIfMissing = true` on a public-info leaf and
`publicInfoInventoryFile = "/absolute/path/to/nix-secrets.toml"` to embed only
that public value as a first-boot default. Evaluation reads the TOML file and
copies the selected public value into a small store file. A Rust one-shot
installs it into a managed public-info generation only when the destination is
absent; later NixOS switches leave deployed rotations intact. If the TOML
entry is unset, no default unit is generated. The inventory path must be
readable during Nix evaluation.

The normalized public inventory is available as
`config.services.nixSecrets.evaluated`. Its outer shape is
`<hostname>.services.<service>` and
`<hostname>.user-<user>-services.<service>`. A JSON store artifact is available
at `config.system.build.nixSecretsManifest`.

Enable `services.secretsReadyWaiter` to derive readiness gates from the same
tree. It creates one waiter per service. Only units named by `consumerUnits`
receive `Requires=` and `After=` edges. It does not add a dependency to
`multi-user.target` or SSH.

The TUI can save named view profiles with `S`. Profiles live in the repository's
`nix-secrets-profiles.toml`, separately from encrypted secrets. They preserve
the ordered tree attributes, attribute filters, type filter, and audience
filter. Search text is transient and is never written to a profile. Opening
the profile list leaves the current view intact; selecting a profile loads it.
The status pane marks a loaded profile as modified when its view settings
change. `n` saves under a new name, `s` confirms overwriting the selected
profile, and `d` confirms deletion. These controls also work by mouse.
The backend owns the file, writes it atomically, rejects malformed files and
symlinks, and notifies other connected clients when profiles change. A stale
client must reload before writing over another client's update.
