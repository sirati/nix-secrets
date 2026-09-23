# Protocol

This document defines component boundaries and message flow. Wire messages are
versioned, length-delimited, and size-limited. Unknown versions, fields that
change security meaning, duplicate map keys, malformed paths, and trailing data
are rejected.

## Components

- **TUI** evaluates the repository, accepts user input, encrypts and decrypts
  values, asks for deployment consent, and authenticates the final SSH target.
- **Backend** coordinates frontends and atomically manages
  `nix-secrets.toml`. It stores ciphertext only.
- **Deployment relay** carries a byte stream between the TUI and target. It
  does not terminate the target SSH session.
- **Target receiver** validates its requirements and atomically installs an
  user-selected password or passphrase generation.
- **Readiness waiter** checks declared paths by metadata without opening secret
  files. Only consuming units depend on it.

## Command grammar

```text
nix-secrets [SSH_ARG ...] -- REPOSITORY
```

An empty `SSH_ARG` sequence selects a local repository. Otherwise the sequence
is passed as individual arguments to OpenSSH. `REPOSITORY` is exactly one
argument after `--`.

```console
nix-secrets -- ~/config
nix-secrets -p 222 admin@example.net -- ~/config
```

The program does not concatenate arguments into a shell command. Remote
startup invokes a fixed backend command with a framed protocol. The backend
expands a leading `~/` using the remote account's home directory and rejects
other tilde forms, NUL bytes, and paths outside the selected repository.

## Evaluation

The TUI and target consume a canonical JSON result from a fixed flake output.
Its outer shape is:

```text
<hostname>.<services|user-{user}-services>.<service>.<service-defined structure>
```

A leaf definition includes a stable path identifier, a recipient identifier,
the target category (`setup`, `service`, or `backup`), ownership, mode, and
applicable limits. Defaults may be inherited at any tree level, but evaluation
must resolve every leaf before it reaches the protocol.

The evaluation result contains public configuration only: secret identifiers,
recipients, destinations, ownership, modes, and consumers. Secret values stay
in the encrypted TOML store until the TUI decrypts them.

For deployment, the frontend compares every selected leaf from its fresh
evaluation with the target's generated manifest, including identifier,
recipients, destination, owner, group, mode, and consumers.

## Local backend discovery

The configured socket path is preferred. The default is:

```text
$XDG_RUNTIME_DIR/nix-secrets/<repository-id>.sock
```

Before protocol negotiation, each side obtains Unix peer credentials from the
kernel. The connection is accepted only when the peer effective UID is the
expected repository user. A stale socket, wrong owner, non-socket node, or
unexpected peer causes failure.

If no valid backend exists, the frontend starts it through a fixed `nix run`
application and passes the repository and evaluated configuration as distinct
arguments or framed input. The backend publishes its socket only after it is
ready. Concurrent starters converge on the one process that successfully binds
the socket.

## Stored record

`nix-secrets.toml` maps stable schema paths to records containing:

- an opaque random version identifier;
- the public recipient fingerprints/key identifiers;
- one base64-encoded complete age ciphertext.

The canonical full schema path is the secret identifier. Lookup, schema
resolution, recipient selection, and destination resolution use only this
identifier. The opaque version ID is revision metadata and never participates
in those decisions.

The configured SSH public keys remain plaintext Nix schema metadata. They are
not encrypted or duplicated into the TOML record. The record contains no SSH
private key.

For encryption, the frontend runs `age --encrypt` with one `--recipient`
argument for every configured SSH public key. It sends the complete plaintext
payload through stdin and reads the complete age file from stdout. The compact
payload contains a fixed tag and format version, canonical identifier, opaque
version ID, and raw secret bytes. Age authenticates all of it.

On decryption, the requested identifier must equal both the outer TOML map key
and authenticated inner identifier. The outer and authenticated inner version
IDs must also match. A mismatch rejects the whole record. Replacing a value at
the same identifier generates a new opaque version and ciphertext while
remaining compatible with the same schema leaf, recipients, and destination.

## Editing flow

1. The TUI obtains the resolved manifest and current encrypted records.
2. It displays leaves as `set` or `unset` based only on record existence.
3. Enter accepts masked input; paste on a selected leaf accepts clipboard
   input. Replacement requires confirmation.
4. The TUI sends the secret to age through a pipe and zeroizes its plaintext
   buffer after use.
5. The backend validates the leaf, record size, and recipient IDs without
   decrypting the age ciphertext.
6. It locks, writes, synchronizes, and atomically replaces
   `nix-secrets.toml`. Other frontends see the update on their next read.

The backend serializes updates under an advisory lock and atomically replaces
the complete ciphertext store.

## Deployment transport

The frontend constructs a direct SSH session to the final target. Intermediate
components expose only a byte-transparent forwarding channel, equivalent to a
strict ProxyCommand. They cannot supply host-key decisions on behalf of the
frontend.

The frontend uses the user's OpenSSH host-key policy and `known_hosts` files.
A changed key aborts. For an unknown key, the UI shows the presented key and
lists known hostnames that already associate with it before asking for an
explicit decision.

SSH-agent keys may authenticate either SSH hop. Recipient decryption instead
uses `age --decrypt -j 1p`: `age-plugin-1p` obtains the matching private key
from 1Password through `op`. This allows 1Password to authorize access without
placing a key file in the repository or frontend configuration. It is separate
from the SSH-agent signing protocol.

## Deployment flow

1. The frontend sends a bounded selection of canonical leaf identifiers.
2. The target resolves that selection only from its generated Nix-store
   manifest and returns the exact public leaf metadata plus current opaque
   versions. The frontend compares every field with its fresh evaluation. Any
   extra, duplicate, differently configured, or unresolved leaf aborts.
3. The TUI presents one modal listing the target, leaves, create/replace state,
   and SSH recipient identities required to decrypt them.
4. After approval, the TUI invokes the 1Password-backed provider. Rejection or
   unlock failure leaves the modal available for retry and sends no plaintext.
5. The TUI decrypts locally and sends each leaf, its stable identifier, and its
   opaque version inside the end-to-end SSH channel.
6. The target independently validates identifiers, paths, sizes, ownership,
   permissions, completeness, and exact selected set.
7. The target stages the whole generation on the persistent destination
   filesystem, writes with restrictive permissions, synchronizes it, and
   atomically publishes it. Any failure preserves the previous generation.
8. The target reports only success or a structured error and erases transient
   plaintext buffers as far as its safe-language and library interfaces allow.

The final layout is:

```text
/persistent/secrets/<service>/<setup|service|backup>/<secret>
```

Path components come from the validated manifest. Absolute components,
`..`, symlink traversal, hard-link substitution, device nodes, and unexpected
owners are rejected.

## Generated-secret tasks

A generated leaf has `kind = "generated"` and a `generatedSecret` declaration
instead of a direct destination. Its canonical identifier remains the map key
in `nix-secrets.toml`. The age ciphertext at that key contains the ephemeral
task input; it is never interpreted as the generated output.

The `storage-box-ssh-key` task declares its output destination and public
bootstrap parameters: Storage Box host, port, user and one or more complete
pinned OpenSSH host public-key lines. Selection and target-state messages keep
ordinary secrets and tasks in distinct arrays. This prevents a receiver from
silently treating a task password as file contents.

After target-state comparison and approval, a task entry contains the stable
identifier, ciphertext version, password and exactly 32 frontend CSPRNG bytes.
The password and contribution are zeroized and are carried only inside the
authenticated SSH stream. The receiver rejects an entry if its task type,
identifier, version, recipients, output or bootstrap metadata differs from the
Nix-generated manifest.

The receiver writes the full frontend contribution to `/dev/urandom` with an
ordinary write before requesting target-local randomness for key generation.
It neither uses `RNDADDENTROPY` nor claims entropy credit. Tests replace both
operations with injected implementations and assert the ordering without
changing the host random pool.

The receiver connects in-process to the Storage Box, verifies the configured
host key, password-authenticates, and updates `.ssh/authorized_keys` through
SFTP. It preserves unrelated entries and allows exactly one entry with the
stable prefix `nix-secrets:<target-host>:<task-id>:`. A retry reuses an existing
valid output key; if a crash occurred after the remote update but before local
publication, retry replaces the marked remote entry before publishing a new
local key. Malformed or duplicate marker entries fail closed.

The generated private key is published atomically at its declared persistent
destination only after remote reconciliation succeeds. Task passwords,
frontend contributions and target seeds never enter a secret generation.

## Readiness

The NixOS module derives expected files from the same resolved manifest. The
waiter checks file existence, type, owner, group, and mode once per second by
metadata operations. Its service account cannot read secret contents.

Each consuming unit declares `Requires=` and `After=` on the waiter for its own
secret set. No global dependency is added to `multi-user.target`. SSH starts
without secrets so initial deployment and repair remain possible. A machine is
not considered boot-successful while required application units remain
unhealthy.
