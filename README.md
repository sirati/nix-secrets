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
$ nix-secrets -- ~/devel/nix/sirati-nixos
```

Otherwise every argument before `--` is passed directly to OpenSSH:

```console
$ nix-secrets -p 222 user@workstation -- ~/devel/nix/sirati-nixos
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

The declaration can set a default SSH encryption recipient for the whole tree
and override it at any subtree or leaf. Transport host keys remain a separate
use of SSH keys and authenticate connections.

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

The backend stores ciphertext and public metadata in `nix-secrets.toml`.
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
signing API. Per-request prompts depend on 1Password policy and session state.
See [AGE-PLUGIN-1P-REVIEW.md](AGE-PLUGIN-1P-REVIEW.md).

The flake keeps runtime tools opt in. Use `.#nix-secrets-1password` for the
1Password provider. Use `.#nix-secrets-age` together with
`--secret-identity /runtime/path/to/key` for a private identity file. The bare
package expects compatible `age` and OpenSSH programs already in `PATH`.

## Deployment

The TUI establishes the SSH connection to the final target through the
backend and deployment relay as a byte-transparent path. The TUI performs host
key verification against its own `known_hosts`: a changed key is rejected and
an unknown key requires a warning that also identifies any known names using
that key.

Press `d` on a set leaf to request deployment. The frontend sends that
identifier to the authenticated target, which resolves it from its generated
manifest and returns its current opaque version. The TUI then displays whether
the value will be created or replaced and asks for approval. It decrypts an
approved value locally and sends plaintext only inside the end-to-end SSH
connection to the target. Unknown SSH host keys require a separate approval
before the target manifest is read.

The target validates the request again, stages the complete update, and then
atomically publishes it below:

```text
/persistent/secrets/<service>/<setup|service|backup>/<secret>
```

Only a consuming service depends on its readiness waiter. SSH remains
available independently so a fresh installation can receive secrets. Missing
secrets keep their consumers unavailable, which also prevents a machine with
required services missing from being marked as a successful boot.

See [PROTOCOL.md](PROTOCOL.md) for message flow and
[THREAT-MODEL.md](THREAT-MODEL.md) for the security boundary.

## License

This project is available under the [MIT License](LICENSE).
