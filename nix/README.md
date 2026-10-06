# Nix interface

Import `nixosModules.default` and enable `services.nixSecrets`. Declarations
contain public metadata. The TUI and the receiver manage the values.

| Leaf setting | Purpose |
| --- | --- |
| `valueType = "password"` | Password/passphrase generation and format limits |
| `valueType = "key"` | Key classification in the TUI |
| `description` | Explain the value to the operator |
| `humanFacing = true` | Include in the human-facing view |
| `externalInputRequired = true` | Must be supplied from an external system |

`externalInputRequired` defaults to false. The Required view uses only this
flag. The value's type and whether it is unset do not affect that view.

Use `destination.contentType` for format validation (`openssh-private-key`,
`openssh-public-key` or `named-ssh-ed25519-public-keys`). For a stored OpenSSH
private key, the store keeps the public half next to the ciphertext, so the TUI
can copy it without decrypting.

Presentation settings do not change identifiers or deployed paths. A service's
`displayPath` sets its group in the TUI. A leaf's `identity` overrides the
semantic `service`, `responsibility`, `namespace` and `name`. `host`, `scope`
and `user` come from the declaration. `presentation` can supply `explanation`,
`facing` and `type`. Semantic identities must be unique.

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

Leaves with `optional = true` may stay unset. Deployment skips them without
generating a value, and they do not block service startup. If you provide a
value, it is validated and deployed as usual. `optional = true` cannot be
combined with `requiredForInstall = true`.

During deployment the target generates unset password leaves and leaves that
declare `valueGenerator`, unless they set `externalInputRequired = true` or
`generateOnDeploy = false`. See [Generation](#generation) for the `valueGenerator` format.

`derivedFrom = { identifier; prefix; suffix; tomlPath; }` deploys the value of
another stored secret, with framing added, in place of a value of its own. See [Derived values](#derived-values).

`kind = "operator"` declares a value that only the operator uses, with an
optional `generator = { installable; args; }`. It is never deployed.
`lib.operatorPublicKey STORE IDENTIFIER` returns its stored public key as
base64, or null. See [Operator-only values](#operator-only-values).

While the leaf has no value in `storeFile`, `requiredForInstall = true` makes
evaluation fail with an error that names the identifier. `requiredBeforeInstall`
adds identifiers declared elsewhere. See [Install prerequisites](#install-prerequisites).

`consumerConstraints` is only for the limits of the consuming program. For
example, if a program rejects values longer than 64 characters, declare
`consumerConstraints.cannotHandleLongerThan = 64;`. The optional fields are
`cannotHandleShorterThan`, `cannotHandleLongerThan`, and `matchingRegex`.
The TUI enforces them for typed passwords that you enter, paste, or generate.

For a task that turns a password into a key, see [Storage Box setup](../STORAGE-BOX-BOOTSTRAP.md).
Generated outputs go through the same destination uniqueness and service
readiness checks as ordinary secret files.

To name recipients once, set
`recipientPublicKeys = { primary = "ssh-ed25519 ..."; };` and
`defaultRecipientNames = [ "primary" ];` at `services.nixSecrets`. A service
can set `recipientNames`, a subtree can set `_recipientNames`, and a leaf can
set `recipientNames`. The existing `defaultRecipientPublicKeys`, service
`recipientPublicKeys`, subtree `_recipientPublicKeys`, and leaf
`recipientPublicKeys` lists still work. New TOML records refer to a versioned
recipient name. The top-level registry keeps older identities after rotation.

Public information uses a leaf with `kind = "public-info"`,
`sharedPublicId = "storage-box/known-hosts"`, `expectedSshHost`, and
`expectedSshPort`. Its destination is the corresponding
`/persistent/public-info/storage-box/known-hosts`, owned by root with mode
`0644` and `contentType = "ssh-known-hosts"`. The value contains pinned
known-hosts lines, stored in plaintext under
`[public_info."storage-box/known-hosts"]` in `nix-secrets.toml`. You can deploy
the same value to several hosts. Each target checks the host, port, key format
and destination again. Public-info leaves never create a secrets readiness
waiter. `expectedSshHosts` allows additional hostnames. You can pin more than
one host key. All leaves that share an ID must have the same validation
settings. These features need receiver protocol 4.

Set `deployment.publishHostIdentityTo` to this host's shared public-info leaf
to publish the SSH identity that the client verified. When that leaf is
selected, preparation fills its empty entries and the original deployment sends
them. Replacing an existing identity requires a separate approval in the client
TUI before that deployment. Other consumers that have the leaf deployed get
their own deployment requests. The producing host gets no extra request for its
own trust file.

To embed only that public value as a default for first boot, set
`installDefaultIfMissing = true` on a public-info leaf and
`publicInfoInventoryFile = "/absolute/path/to/nix-secrets.toml"`. Evaluation
reads the TOML file and copies the selected public value into a small store
file. A Rust one-shot unit installs it into a managed public-info generation
only if the destination does not exist. Later NixOS switches leave deployed
rotations in place. If the stored public value is missing, the unit uses a
declared `defaultValue`. Without either value, no default unit is generated.
Nix evaluation must be able to read the inventory path.

`config.services.nixSecrets.evaluated` contains the normalized public
inventory. Its outer shape is `<hostname>.services.<service>` and
`<hostname>.user-<user>-services.<service>`. A JSON store artifact is available
at `config.system.build.nixSecretsManifest`.

Enable `services.secretsReadyWaiter` to derive readiness gates from the same
tree. It creates one waiter per service. Only units named in `consumerUnits`
receive `Requires=` and `After=` edges. It does not add a dependency to
`multi-user.target` or SSH.


## Generation

A deployment does not stop at the first unset value. When a requested value is
unset in `nix-secrets.toml`, the target generates and installs it, and returns
only an age ciphertext for its recipients. The TUI checks the recipients
without decrypting and stores the record with the usual conditional write. The
approval dialog lists these values as "will generate N values on the target",
and a notice lists them after deployment. The target never regenerates values
that already exist.

The target generates a leaf when it is unset and:

- has `valueType = "password"`. The result is a 32-character password, or the
  length and alphabet that its `consumerConstraints` allow; or
- declares `valueGenerator`, which fixes the exact bytes:

```nix
# prefix + encode(<bytes> random bytes) + suffix, byte for byte.
valueGenerator = {
  kind = "random-bytes";
  bytes = 32;               # 16 through 1024
  encoding = "base64";      # "base64" (padded), "base64url" (unpadded), or "hex"
  prefix = "";              # optional literal text, at most 1024 bytes
  suffix = "";              # optional literal text, e.g. "\n"
};
```

The target never generates a leaf that is public information, has
`externalInputRequired = true`, or sets `generateOnDeploy = false`. Set
`generateOnDeploy = false` for a value that must equal another leaf's value,
such as a key shared by two hosts. Otherwise each host generates its own. A
`valueType = "key"` leaf without `valueGenerator` is never generated, because
its format is unknown. If the target cannot generate a requested value, it does
not deploy that value and lists it with the reason, such as
"generateOnDeploy = false". All other values deploy.

## Derived values

`derivedFrom` deploys a framed copy of another stored secret that is not itself
derived. The derived leaf has no ciphertext or editable value of its own:

```nix
secrets.credentials = {
  destination = { /* path, category, owner, group, mode */ };
  derivedFrom = {
    identifier = "HOST.services.app.token";
    prefix = "token=";
    suffix = "\n";
    # Optional: select a string field if the source is TOML.
    # tomlPath = [ "authentication" "token" ];
  };
};
```

The deployed bytes are `prefix + source + suffix`. Set `encoding = "pgpass"`
to escape colons and backslashes in the password. Line breaks and NUL are
rejected. A change to the source, framing, encoding or `tomlPath` changes the
derived version. A missing TOML field or invalid TOML is an error.

If the same deployment generates the source, the target derives the value and
publishes both atomically. It returns only the source ciphertext. If an unset
symmetric source belongs to another host, the first host deployed may generate
it, using the source's generator and recipients. Its ciphertext is stored under
the source identifier, and later deployments reuse it. Private keys are
generated only on the host that owns them. Other missing sources are skipped.

Generation on the target needs receiver protocol 2. Generating a source for
another host and `tomlPath` need protocol 3. An older receiver can still
receive values that are already stored and use no unsupported features.

## Operator-only values

`kind = "operator"` stores an encrypted value with no deployment destination.
Target manifests, readiness checks and deployment requests exclude it. An
optional keypair generator runs on the operator's machine on request:

```nix
services.nixSecrets.services.signing.secrets.private-key = {
  kind = "operator";
  generator = {
    installable = "github:owner/signing-tool#signer";
    args = [ "keygen" "--stdio" ];
  };
};
```

The generator runs as `nix run INSTALLABLE -- ARGS` with empty stdin. The
arguments are public metadata. The generator must exit 0, write the private key
to stdout (at most 1 MiB), write the public key to fd 3 (at most 64 KiB), and
write neither key to disk. The TUI shows stderr if the generator fails.

The private key is stored encrypted. The public output is stored as base64 in
`public_key`. `lib.operatorPublicKey STORE IDENTIFIER` returns that public
value, or null, without decrypting. The TUI copies printable public keys as
text and binary keys as base64.

## Install prerequisites

Set `requiredForInstall = true` on a leaf that is not derived when evaluation
needs its stored value or public key. `requiredBeforeInstall` lists more
identifiers declared elsewhere:

```nix
services.nixSecrets = {
  storeFile = toString ./nix-secrets.toml;
  requiredBeforeInstall = [ "HOST.services.signing.private-key" ];
};
```

Evaluation fails and names the missing identifier. Operator keys with
generators need their stored public half. Public-info leaves need their shared
record or a default. Other leaves need an encrypted record.
`storeFile` defaults to `publicInfoInventoryFile`.

`lib.requireOperatorPublicKey STORE IDENTIFIER` returns the public key as
base64, and fails where `lib.operatorPublicKey` would return null. These helpers
read only public metadata. Deliver runtime service secrets by deployment. Do
not read them during evaluation.

## Target-local SSH keys

A `generatedSecret` with `type = "local-ssh-key"` generates an Ed25519 private
key on its target, or reuses an existing one. `output` has the same path,
category, ownership, mode and content-type fields as a destination. The private
key never goes back to the operator. Its public key, with a date, is stored as
metadata.

The optional `generatedSecret.registerAt` names an encrypted inventory of public
keys. Declare that destination with
`contentType = "named-ssh-ed25519-public-keys"` and
`authorizedForUser = "ACCOUNT"`. The receiver accepts only uniquely named
Ed25519 keys. After registration updates the inventory, a separate deployment
approval installs it on the receiving host. Conditional writes and read-back
checks stop one operator from silently overwriting another operator's
registrations.

## Deployment audit

Each successful receiver transaction writes a root-owned event that contains no
secret values under `/run/nix-secrets/audit/`. The event records the target,
the time, the identifiers, the names of the receiving SSH account and key, and
which values were newly set and which were replaced. `receiver.auditGroup` lets
reporters read these events without giving them access to secret files.

`receiver.postDeployCommand` runs a configured executable from `/nix/store`
after publication and before the receiver reports success. For example, it can
restore ACLs on container credentials. Its output does not go into the
deployment protocol. If it fails, the receiver reports failure, and the
published values stay installed.
