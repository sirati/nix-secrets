# Nix interface

Import `nixosModules.default` and enable `services.nixSecrets`. Declarations
contain public metadata; values are managed by the TUI and receiver.

| Leaf setting | Purpose |
| --- | --- |
| `valueType = "password"` | Password/passphrase generation and format limits |
| `valueType = "key"` | Key classification in the TUI |
| `description` | Explain the value to the operator |
| `humanFacing = true` | Include in the human-facing view |
| `externalInputRequired = true` | Must be supplied from an external system |

`externalInputRequired` defaults to false. The Required view uses this flag,
not the value's type or whether it is unset.

Use `destination.contentType` for format validation (`openssh-private-key`,
`openssh-public-key` or `named-ssh-ed25519-public-keys`). A stored OpenSSH
private key keeps its public half beside the ciphertext, so the TUI can copy
it without decryption.

Presentation does not change identifiers or deployed paths. A service's
`displayPath` groups it in the TUI; leaf `identity` overrides semantic
`service`, `responsibility`, `namespace` and `name`, while `host`, `scope` and
`user` come from the declaration. `presentation` optionally supplies
`explanation`, `facing` and `type`. Semantic identities must be unique.

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

`optional = true` leaves may remain unset: deployment skips them without
generation, and they do not gate service startup. Provided values are validated
and deployed normally. This cannot be combined with `requiredForInstall = true`.

Unset password leaves, and leaves declaring `valueGenerator`, are generated
on the target during deployment unless they set `externalInputRequired = true`
or `generateOnDeploy = false`. See [Generation](#generation) for the `valueGenerator` format.

`derivedFrom = { identifier; prefix; suffix; tomlPath; }` deploys another stored
secret's value, framed, instead of a value of its own; see [Derived values](#derived-values).

`kind = "operator"` declares an operator-only value with an optional
`generator = { installable; args; }`; it is never deployed. `lib.operatorPublicKey
STORE IDENTIFIER` returns its stored public key as base64, or null. See
[Operator-only values](#operator-only-values).

`requiredForInstall = true` makes evaluation fail, naming the identifier,
while the leaf has no value in `storeFile`; `requiredBeforeInstall` adds
identifiers declared elsewhere. See [Install prerequisites](#install-prerequisites).

Only consumer compatibility limits belong in `consumerConstraints`. For example,
if a program rejects values longer than 64 characters, declare
`consumerConstraints.cannotHandleLongerThan = 64;`. The optional fields are
`cannotHandleShorterThan`, `cannotHandleLongerThan`, and `matchingRegex`.
They are enforced for typed passwords entered, pasted, or generated in the TUI.

For a password-to-key bootstrap task, see [Storage Box setup](../STORAGE-BOX-BOOTSTRAP.md).
Generated outputs use the same destination uniqueness and service-readiness
checks as ordinary secret files.

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
`0644` and `contentType = "ssh-known-hosts"`. The value contains pinned known-hosts lines, stored in plaintext under
`[public_info."storage-box/known-hosts"]` in `nix-secrets.toml`. The same value
can be deployed to multiple hosts; each target checks the host, port, key
format, and destination again. Public-info leaves never create a
secrets-readiness waiter. `expectedSshHosts` allows additional hostnames.
Multiple host-key pins are allowed. All leaves sharing an ID must
agree on their validation settings. These features need receiver protocol 4.

Set `deployment.publishHostIdentityTo` to this host's shared public-info leaf
to publish the SSH identity verified by the client during deployment. Empty
entries are filled automatically. Replacing an existing identity requires
separate client TUI approval, followed by normal deployment to its consumers.

Set `installDefaultIfMissing = true` on a public-info leaf and
`publicInfoInventoryFile = "/absolute/path/to/nix-secrets.toml"` to embed only
that public value as a first-boot default. Evaluation reads the TOML file and
copies the selected public value into a small store file. A Rust one-shot
installs it into a managed public-info generation only when the destination is
absent; later NixOS switches leave deployed rotations intact. A declared `defaultValue` is used when the stored public value is missing.
Without either value, no default unit is generated. The inventory path must be
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


## Generation

A deployment never stops on the first unset value. When a requested value is
unset in `nix-secrets.toml`, the target generates it itself, installs it, and
returns only an age ciphertext for its recipients. The TUI verifies the
recipients without decrypting and stores the record through the normal
conditional write. The approval dialog lists these values as "will generate N
values on the target", and a notice lists them after deployment. Values that
already exist are never regenerated.

A leaf is generated when it is unset and:

- has `valueType = "password"`: a 32-character password, or the length and
  alphabet its `consumerConstraints` allow; or
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

A leaf is never generated when it is public information, has
`externalInputRequired = true`, or sets `generateOnDeploy = false`. Set the
latter for a value that must equal another leaf's value, such as a key shared
by two hosts: each host would otherwise generate its own. A `valueType = "key"`
leaf without `valueGenerator` is never generated, since its format is unknown.
If a requested value cannot be generated, it is not deployed and is listed
with its reason, such as "generateOnDeploy = false"; everything else deploys.

## Derived values

`derivedFrom` deploys a framed copy of another stored, non-derived secret. It
has no independent ciphertext or editable value:

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
to escape password colons and backslashes; line breaks and NUL are rejected.
Changes to the source, framing, encoding or `tomlPath` change the derived version. A missing TOML field or
invalid TOML is an error.

If the source is generated during the same deployment, the target derives the
value and publishes both atomically; only the source ciphertext is returned.
An unset symmetric source owned by another host may be generated by the first
host deployed, using the source's generator and recipients. Its ciphertext is
stored under the source identifier; later deployments reuse it. Private keys
are generated only on their owning host. Other missing sources are skipped.

Target generation needs receiver protocol 2. Cross-host source generation and
`tomlPath` need protocol 3. An older receiver can still receive already-stored
values that do not use unsupported features.

## Operator-only values

`kind = "operator"` stores an encrypted value without a deployment destination.
It is excluded from target manifests, readiness checks and deployment requests.
An optional keypair generator runs on the operator's machine when requested:

```nix
services.nixSecrets.services.signing.secrets.private-key = {
  kind = "operator";
  generator = {
    installable = "github:owner/signing-tool#signer";
    args = [ "keygen" "--stdio" ];
  };
};
```

The generator runs as `nix run INSTALLABLE -- ARGS` with empty stdin. Arguments
are public metadata. It must exit 0, write the private key to stdout (at most
1 MiB), write the public key to fd 3 (at most 64 KiB), and write neither key to
disk. Stderr is displayed on failure.

The private key is encrypted; the public output is stored as base64 in
`public_key`. `lib.operatorPublicKey STORE IDENTIFIER` returns that public
value or null without decryption. The TUI copies printable public keys as text
and binary keys as base64.

## Install prerequisites

Set `requiredForInstall = true` on a non-derived leaf when its stored value or
public key is required for evaluation. `requiredBeforeInstall` lists additional
identifiers declared elsewhere:

```nix
services.nixSecrets = {
  storeFile = toString ./nix-secrets.toml;
  requiredBeforeInstall = [ "HOST.services.signing.private-key" ];
};
```

Evaluation fails with the missing identifier. Operator keys with generators
require their stored public half; public-info leaves require their shared
record or default; other leaves require an encrypted record.
`storeFile` defaults to `publicInfoInventoryFile`.

`lib.requireOperatorPublicKey STORE IDENTIFIER` returns the public key as
base64 or fails instead of returning null. These helpers read public metadata
only. Runtime service secrets belong in deployment, not evaluation.

## Target-local SSH keys

A `generatedSecret` with `type = "local-ssh-key"` generates or reuses an
Ed25519 private key on its target. `output` has the same path, category,
ownership, mode and content-type fields as a destination. The private key never
returns to the operator; its dated public key is stored as metadata.

Optional `generatedSecret.registerAt` names an encrypted public-key inventory.
Declare that destination with `contentType = "named-ssh-ed25519-public-keys"`
and `authorizedForUser = "ACCOUNT"`. The receiver accepts only unique named
Ed25519 keys. After registration updates the inventory, a separate deployment
approval installs it on the receiving host. Conditional writes and read-back
checks prevent silently overwriting another operator's registrations.

## Deployment audit

Successful receiver transactions write root-owned, value-free events under
`/run/nix-secrets/audit/`: target, time, identifiers, receiving SSH account/key
names, and newly set versus replaced values. `receiver.auditGroup` grants
reporters access to these events without granting access to secret files.

`receiver.postDeployCommand` runs a configured executable from `/nix/store`
after publication and before success is returned, for example to restore
container credential ACLs. Its output stays outside the deployment protocol.
If it fails, the receiver reports failure; the published values remain installed.
