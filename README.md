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

### Using a secret in another program

```text
nix-secrets pipe-secret [OPTIONS] IDENTIFIER -- COMMAND [ARGUMENT ...]
nix-secrets pipe-secret [OPTIONS] IDENTIFIER
```

`pipe-secret` decrypts one stored value through the normal provider, including
the one-shot 1Password launcher, and hands it on without writing it to disk.
With `-- COMMAND` it runs the command with the value on its stdin and exits
with the command's status. Without it, the value is written to stdout for a
pipeline; stdout must not be a terminal, and nothing else is ever written to
stdout. The repository defaults to the working directory; `--repository PATH`,
`--secret-identity PATH` and `--1password-shared-session` work as for the TUI.

```console
$ nix-secrets pipe-secret host.services.nmbl.generation-key -- \
    nmbl-sign sign --key-stdin --domain generation image.efi
$ nix-secrets pipe-secret host.services.nmbl.generation-key | nmbl-sign sign --key-stdin …
```

The second form is what a `keyCommand = [ "nix-secrets" "pipe-secret" "<id>" ]`
option runs.

## Declared secret tree

The program evaluates the repository and consumes this shape:

```text
<hostname>.<services|user-{user}-services>.<service>.<service-defined structure>
```

Leaves are secrets. The TUI presents the structure as a file tree and marks
each leaf `set` in green or `unset` in red. Pressing Enter opens a masked input
editor. Pasting while a leaf is selected sets it from the clipboard, and a
paste in the entry field inserts the pasted text. Ctrl+V reads the local
clipboard directly, only when pressed: it reads the X11 CLIPBOARD selection
in-process, over Xwayland under Wayland, with an unmapped helper window, so no
window appears. `wl-paste` is not used because on compositors without a
data-control protocol, such as GNOME, it maps a window for every read. It
works even when the terminal refuses to paste; held keys read once, and one
trailing newline is dropped.
Clicking an unset input value selects it and opens its entry field. While a
search is active, the status line counts matches and those hidden by filters.
Attributes that do not apply to a value, such as the user of a system
service, add no tree level or filter value; a filter on them leaves such
values visible. Replacing
an existing value requires confirmation after the new value is entered and
saved with Enter; declining returns to the entry field with the typed value.
Ctrl+R or the "Reveal current" button in that field or the confirmation
shows the stored value, and closing it returns to the dialog. Before
confirming, the backend compares the stored record with `HEAD:nix-secrets.toml`; only HEAD is checked, not older
commits. If the value is not in HEAD, or git cannot answer, a warning explains
that overwriting loses the old value for good. Only Ctrl+Shift+Y or its Yes
button confirms; n, Enter, Space and Esc keep the value. `O` opens session
settings, which reset on restart and are never written to the repository. With
"Autosave unset on paste" on, toggled by Tab or a click in the entry field, a
one-line paste into an unset value saves it at once.
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

### Operator-only secrets

A leaf with `kind = "operator"` is stored encrypted for its recipients like any
other secret, but it has no destination. It never enters a host manifest, a
deployment request, a readiness waiter, or deployment's missing-value checks.
Use it for keys only the operator uses, such as image or closure signing keys.
Set, reveal, paste and delete work as for other values. The TUI shows it as an
operator key, in the Keys view.

An operator leaf may declare a keypair generator. nix-secrets stays
independent of any key tool: the consumer names a flake installable and its
arguments, and the TUI's `g` runs it on the operator's machine only when asked:

```nix
services.nixSecrets.services.nmbl.secrets.generation-key = {
  kind = "operator";
  description = "NMBL boot generation signing key";
  generator = {
    installable = "github:sirati/siratis-nmbl-bootloader?dir=sirati-nmbl/nmbl-init-rs#nmbl-sign";
    args = [ "keygen" "--alg" "ml-dsa-65" "--stdio" ];
  };
};
```

The generator contract:

- it is run as `nix run INSTALLABLE -- ARGS…` with an empty stdin; `args`
  are public schema data and must not contain secrets;
- it writes the private key, byte for byte as it should be stored, to stdout
  (at most 1 MiB);
- it writes the public key, byte for byte, to file descriptor 3 (at most
  64 KiB);
- it writes neither to disk and exits 0; stderr is shown only on failure.

The test suite checks this contract with a scripted generator. Set
`NIX_SECRETS_NMBL_SIGN=/path/to/nmbl-sign` when running `cargo test` to also
generate an ML-DSA-65 key with NMBL, sign through `pipe-secret` and
`nmbl-sign sign --key-stdin`, and verify with the stored public key.

nix-secrets reads both pipes concurrently, encrypts the private key to the
leaf's recipients, and stores the public key in plain, base64-encoded, as
`public_key` beside the ciphertext in `nix-secrets.toml`. `p` copies it: as
text when it is printable, otherwise as base64. The consumer can reference it
from Nix without decrypting anything:

```nix
let
  # Base64 of the generator's fd 3 output, or null while the key is unset.
  encoded = nix-secrets.lib.operatorPublicKey ./nix-secrets.toml
    "server-hetzner2.services.nmbl.generation-key";
in
{
  # A binary key, such as NMBL's raw ML-DSA public key, is decoded in a build
  # step; nothing secret is involved.
  boot.nmbl.signing.publicKeys = lib.optional (encoded != null) (
    pkgs.runCommand "nmbl-generation-key.pub" { } "echo ${encoded} | base64 -d > $out"
  );
}
```

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

### Values generated at deployment

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

For example, a Knot TSIG key file:

```nix
valueGenerator = {
  kind = "random-bytes"; bytes = 32; encoding = "base64";
  prefix = "key:\n  - id: dns-transfer\n    algorithm: hmac-sha256\n    secret: ";
  suffix = "\n";
};
```

A leaf is never generated when it is public information, has
`externalInputRequired = true`, or sets `generateOnDeploy = false`. Set the
latter for a value that must equal another leaf's value, such as a key shared
by two hosts: each host would otherwise generate its own. A `valueType = "key"`
leaf without `valueGenerator` is never generated, since its format is unknown.
If any requested value cannot be generated, the deployment is refused before
anything is generated or written, with one message listing every such value:
"Missing values that must be entered: …".

Generation needs a target running deployment protocol 2, which also must have
been built from the same `valueGenerator` and constraints the TUI evaluates.
An older target still receives values that are already set.

See [PROTOCOL.md](PROTOCOL.md) for message flow and
[THREAT-MODEL.md](THREAT-MODEL.md) for the security boundary.

## License

This project is available under the [MIT License](LICENSE).
