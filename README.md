# nix-secrets

`nix-secrets` is a repository-aware TUI for editing encrypted secrets and
deploying them to NixOS machines. Nix declares the required secret tree and
its recipients; secret plaintext never becomes a Nix value, derivation, store
path, command-line argument, or Git object.

The repository contains a Rust workspace with frontend, backend, deployment
relay, and target programs. A NixOS module turns the same evaluated declaration
into target paths, readiness checks, and service dependencies.

## Invocation

The command grammar is:

```text
nix-secrets [SSH_ARG ...] -- REPOSITORY
```

When no argument appears before `--`, the repository and backend are local:

```console
$ nix-secrets -- ~/projects/infrastructure
```

Otherwise every argument before `--` is passed directly to OpenSSH:

```console
$ nix-secrets -p 222 user@workstation -- ~/projects/infrastructure
```

`REPOSITORY` is one argument. On a remote backend, a leading `~/` is expanded
by the backend from that account's home directory. It is not expanded by a
remote shell. The launcher uses a fixed remote command and protocol; it never
constructs a shell command from these arguments.

## Declared secret tree

The program evaluates the repository and consumes this shape:

```text
<hostname>.<services|user-{user}-services>.<service>.<service-defined structure>
```

Leaves are secrets. The TUI presents the structure as a file tree and marks
each leaf `set` in green or `unset` in red. Pressing Enter opens a masked input
editor. Pasting while a leaf is selected sets it from the clipboard. Replacing
an existing value requires confirmation.
Press `d` to delete a selected value after confirmation, `r` to reveal it,
`c` to copy it, or `p` to copy the public half of a stored OpenSSH private key
without decrypting. Dialogs appear over the tree. A success notice closes on the
next key or click, which then performs its usual action; above a confirmation
or entry dialog that key only closes the notice. Errors stay until Enter or a
click on OK. Press `1` for values needing operator input, `2` for all items,
`3` for private keys, `4` for passwords, or `5` for public information.
Press `6` for all audiences or `7` for human-facing values; `/` searches names,
identifiers, and descriptions. The views compose. Key and password views use
the declared `valueType`; untyped certificates and other values remain in the
all-items view. A leaf's optional description appears when selected. Local
keys generated on a target do not appear as editable leaves.

For all missing passwords, press `G` and choose `p` for random passwords or
`w` for passphrases. Existing values are never replaced by this action.
For one password leaf, press `g` and choose `p` for a random password or `w` for
a word passphrase. The preview starts masked; `r` reveals it, `c` copies it,
Enter encrypts and stores it, and Escape discards it. Replacement requires a
separate confirmation. Copy uses `wl-copy` with the value on standard input;
the opt-in `nix-secrets-clipboard` package supplies it without adding a
clipboard dependency to other package outputs.

The declaration can name SSH encryption recipients once and select them by
name for the whole tree, a subtree, or a leaf. Recipient rotations retain
earlier key identities in the TOML registry so existing ciphertext remains
decryptable. Transport host keys authenticate connections separately.

## Backend

The frontend connects to a Unix socket selected by repository configuration,
or by default:

```text
$XDG_RUNTIME_DIR/nix-secrets/<repository-id>.sock
```

It accepts the socket only when the peer process has the same effective user
as the frontend. If no valid backend is listening, the program starts one with
a fixed `nix run` invocation and the freshly evaluated secret declaration.
Several TUI frontends can share one backend. The backend serializes changes to
`nix-secrets.toml` and replaces that file atomically.
While the TUI is open, the backend pushes change and deployment-request notices
over a subscription. A local worker handles SSH, encryption, decryption, and
deployment work; terminal input and drawing stay on the frontend thread.

The backend stores ciphertext, recipient references, and public metadata in
`nix-secrets.toml`. A shared public-information entry has one plaintext TOML
value even when several hosts deploy it.
Encryption and decryption happen in the TUI process.

## Encryption

The frontend sends the complete secret to `age` through an anonymous pipe.
`age` encrypts and authenticates it directly to every configured ordinary
`ssh-ed25519` or `ssh-rsa` recipient. The resulting age file is base64-encoded
for `nix-secrets.toml`; age alone defines the cryptographic file format.

Before encryption, the frontend prefixes the raw value with a compact payload
containing a fixed format tag, the canonical full schema path, and a random
opaque version ID. Decryption requires the requested path, TOML map key, outer
version ID, and authenticated inner values to agree. Replacing a value creates
a new version and ciphertext without changing its schema identifier.

The default key provider uses `age-plugin-1p`. Encryption needs only the SSH
public key. During decryption the plugin retrieves the matching private key
from 1Password through `op`; neither the TUI nor the repository needs a private
key file. This uses 1Password CLI authorization rather than the SSH-agent
signing API. On Linux, 1Password binds a CLI authorization to the terminal it
came from, or to the session leader when there is no terminal, for 10 minutes
of use. The TUI therefore runs each 1Password decryption through
`nix-secrets-1password`, which starts age as the leader of a new session
without a terminal. Each approval then covers exactly one decryption. It never
reaches your shell, and the prompt names `nix-secrets-1password` as the
requester. Pass `--1password-shared-session` to reuse the terminal's
10-minute authorization instead. While a slow operation runs, a Working strip
shows its name and elapsed time.
See [AGE-PLUGIN-1P-REVIEW.md](AGE-PLUGIN-1P-REVIEW.md).

The flake keeps runtime tools opt in. Use `.#nix-secrets-1password` for the
1Password provider. The desktop-app integration accepts only an `op` that is
setgid `onepassword-cli`; on NixOS enable `programs._1password` so
`/run/wrappers/bin/op` exists. The package appends its own 1Password CLI to the
end of `PATH`, so a system `op` always takes precedence. The bundled one is only
a fallback, for example for `OP_SERVICE_ACCOUNT_TOKEN`. Use `.#nix-secrets-age` together with
`--secret-identity /runtime/path/to/key` for a private identity file. The bare
package expects compatible `age` and OpenSSH programs already in `PATH`.

## Deployment

The TUI establishes the SSH connection to the final target through the
backend and deployment relay as a byte-transparent path. The TUI performs host
key verification against its own `known_hosts`: a changed key is rejected and
an unknown key requires a warning that also identifies any known names using
that key.

The target deployer requests the secrets for a specific server. Connected
frontends receive that request and show the target, the values to create or
replace, and any target-generation tasks. The frontend compares the target's
manifest with its evaluated schema, asks for approval, decrypts the requested
values locally, and sends plaintext only inside the end-to-end SSH connection.
Unknown SSH host keys require a separate approval before the target manifest
is read. Editing or selecting one TUI item never initiates a deployment.

The target validates the request again, stages the complete update, and then
atomically publishes it below:

```text
/persistent/secrets/<service>/<setup|service|backup>/<secret>
```

Only a consuming service depends on its readiness waiter. SSH remains
available independently so a fresh installation can receive secrets. Missing
secrets keep their consumers unavailable, which also prevents a machine with
required services missing from being marked as a successful boot.

Each successful receiver transaction writes a root-owned audit event under
`/run/nix-secrets/audit/`. It records the target hostname, time, secret
identifiers, and whether each secret was newly set or replaced. It never
records secret values. `services.nixSecrets.receiver.auditGroup` grants a
reporter read access to the event without granting access to secret files.

`local-ssh-key` is a generated secret type for an Ed25519 key kept on the
target. The target mixes the operator's random contribution into its kernel
random source, generates or reuses the private key, and returns a dated public
key. Optional `generatedSecret.registerAt` names a stored secret for the
public-key inventory. The operator-side deployer adds the verified target
hostname to the key name and updates that inventory in the encrypted backend.
It queues a separate approval to deploy the changed inventory to its target.
Declare its destination with `contentType = "named-ssh-ed25519-public-keys"`
and `authorizedForUser = "<ssh-account>"`; the receiver then refuses values
that are not unique named Ed25519 public keys. Registration uses a conditional
write followed by a decrypt-and-compare read-back so two operators cannot
silently overwrite each other's key inventory.
Audit events include the receiving SSH account and key names.

See [PROTOCOL.md](PROTOCOL.md) for message flow and
[THREAT-MODEL.md](THREAT-MODEL.md) for the security boundary.

## License

This project is available under the [MIT License](LICENSE).
