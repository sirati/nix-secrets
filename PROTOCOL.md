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
the complete TOML store. Named recipients are stored as versioned references
such as `primary#0`; one top-level registry holds the corresponding key
identity. Existing records with inline `recipient_ids` remain readable, and
rotating a named key adds a new registry revision without changing old records.
Stored OpenSSH private-key records carry the derived public key as plaintext
metadata next to the ciphertext. A target-generated key registers its returned
public half through a version-checked update and read-back; a retry reuses an
existing target private key.

Public-info leaves use a separate plaintext TOML table keyed by stable
`sharedPublicId`. Their updates and deletions use compare-and-set. Deployment
is still requested for a whole target and attested against the Nix manifest.
The privileged target validates the exact known-hosts host, port, Ed25519 key,
destination, ownership, and mode before publishing a world-readable file in
`/persistent/public-info`. These values do not enter secret readiness gates.

## Commits

`CommitSummary` returns the diff stat and status of `nix-secrets.toml` and
`nix-secrets-profiles.toml`, the other staged paths, the message of `HEAD`,
and whether `commit.gpgsign` is set. `Commit { options, forward_agent }`
stages and commits only those two files and refuses while other paths are
staged. With `forward_agent`, the backend serves a temporary agent socket
(0600, in a 0700 directory under `$XDG_RUNTIME_DIR`, same-UID peers only) to
`git -c gpg.ssh.program=ssh-keygen` and forwards each agent message to the
frontend as `AgentRequest { message }`. The frontend answers with
`AgentReply { message }` from its own agent. Both sides pass only
`REQUEST_IDENTITIES` and `SIGN_REQUEST` over an SSHSIG blob in the `git`
namespace; anything else gets `SSH_AGENT_FAILURE`. The exchange ends with
`Committed { result }` or `Error { message }` carrying git's stderr. Agent
messages are limited to 256 KiB. Adding these requests raised the backend
compatibility version to 9.

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

## Values generated at deployment

Deployment protocol 2 lets the target generate stored values that are unset
in the operator store. Plaintext of such a value never leaves the target.

1. Before connecting, the frontend classifies each requested unset leaf. A
   leaf is generatable when it is not public information, not
   `externalInputRequired`, not `generateOnDeploy = false`, and is either
   `valueType = "password"` (password generator under its consumer
   constraints) or declares `valueGenerator`. A Storage Box task whose
   bootstrap input is unset is never generatable. If any requested value is
   not generatable, the frontend refuses the whole deployment with one list of
   all such values and generates, sends and writes nothing. The approval
   dialog shows the same list, or the values the target will generate.
2. The target's state reports, per stored leaf, a canonical `generator`
   description derived from its own manifest. Before sending a generation
   request, the frontend requires this description to equal the one derived
   from its schema, so the target cannot produce a value in another format.
3. The batch carries `generate` entries: identifier and 32 frontend CSPRNG
   bytes. Their identifiers are part of `requested_identifiers` and cannot also
   appear in `entries`.
4. If the target already has a nix-secrets version of the leaf installed, it
   re-encrypts that installed value under its installed version (`adopted`).
   Otherwise it writes the contribution to `/dev/urandom`, generates the value
   from kernel randomness, and chooses a fresh 16-byte version. It encrypts
   the value with the same inner envelope as the frontend (identifier and
   version authenticated inside the age payload) to the leaf's recipient keys
   from its manifest, using the receiver's pinned `age`.
5. The value is staged and published with the rest of the generation. The
   result carries `generated_records`: format version, version, recipient IDs
   and age ciphertext, exactly one per requested identifier.
6. The frontend checks each record without decrypting: format version,
   16-byte version, recipient IDs equal to the schema's, and an age v1 header
   whose stanzas are exactly one `ssh-ed25519`/`ssh-rsa` stanza per schema
   recipient key (matched by age's SHA-256 key tag) and nothing else. It
   stores the record with a conditional write that requires the value to be
   still unset, which also publishes the normal change event.

Retry behaviour: a record lost between target publication and the store write
(connection loss, backend failure) is recovered by deploying again, because the
target adopts the installed value instead of generating a different one. If
someone entered the value in the store meanwhile, the conditional write keeps
that value, the frontend reports it, and the next deployment installs it.

## Derived values

A stored leaf with `derivedFrom = { identifier; prefix; suffix; }` is never
stored or generated. The frontend decrypts the named source, which may belong
to another host, and deploys `prefix + source + suffix` as an ordinary entry.
Its version is `d-` and 32 hex digits of SHA-256 over the length-prefixed
source version, source identifier, prefix and suffix. It changes exactly when
the source value or the framing changes.

If the source is unset and in the same deployment's `generate` list, it is on
the same target, and the batch names the derived value in `derive` instead of
sending it. The target frames it from the value it generated or adopted for
the source and computes the same version. Every target secret reports its
canonical `derived` description, which the frontend compares with its schema
before deploying, so the target frames exactly as declared. A `derive` entry
whose source is not generated in the same batch is rejected. Any other unset
source refuses the
deployment before connecting, naming the source and, when the source is
generatable, the host whose deployment generates it.

## Operator-only values

A `kind = "operator"` leaf has recipients but no destination. The Nix module
removes it from every host manifest and readiness waiter, and the frontend
refuses any deployment request naming it before connecting. Its stored record
may carry `public_key`: base64 of the public key its declared generator wrote
to file descriptor 3. The generator runs on the operator's machine as
`nix run INSTALLABLE -- ARGS…` with stdin from `/dev/null`, the private key on
stdout (at most 1 MiB) and the public key on fd 3 (at most 64 KiB). The private
key is encrypted before it is stored; neither half is written to disk.

`nix-secrets pipe-secret ID [-- COMMAND…]` decrypts one stored value and
writes it to the command's stdin, or to a stdout that is not a terminal.

## Generated-secret tasks

A generated leaf has `kind = "generated"` and a `generatedSecret` declaration
instead of a direct destination. Storage Box tasks store an encrypted bootstrap
password at their canonical identifier; that input is never interpreted as
the generated output. Local SSH key tasks need no stored input and are absent
from the editable TUI tree. They are generated on the target during deployment.

The `storage-box-ssh-key` task declares its output destination and public
bootstrap parameters: Storage Box host, port, user and one or more complete
pinned OpenSSH host public-key lines. Selection and target-state messages keep
ordinary secrets and tasks in distinct arrays. This prevents a receiver from
silently treating a task password as file contents.

After target-state comparison and approval, a Storage Box task entry contains
the stable identifier, ciphertext version, password and exactly 32 frontend
CSPRNG bytes. A local SSH key task uses no password. Sensitive inputs are
zeroized and carried only inside the
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
