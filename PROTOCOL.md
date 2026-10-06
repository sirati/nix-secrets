# Protocol

## Backend socket

The socket is `$XDG_RUNTIME_DIR/nix-secrets/backend-v22-<hash>.sock`, where
`<hash>` is 16 hex digits hashed from the canonical repository path and 22 is
the compatibility version. A `.lock` file next to it belongs to the running
backend. A starter never removes the socket of a backend that holds the lock.
A backend whose socket is removed or replaced exits.

Both sides read the peer's credentials from the kernel before anything else
and drop the connection unless the peer's effective UID equals their own. A
socket node with another owner is refused.

Each message is a 4-byte big-endian length followed by a JSON object of at
most 8 MiB. Requests are tagged by `"operation"` and responses by `"status"`,
in kebab-case. `RequestSecrets` below is `"operation": "request-secrets"`.
Unknown fields are rejected.

`GetSchema` returns the backend's evaluated schema, its age, and whether
requests wait. A TUI uses it when requests wait or when it is at most 120
seconds old.

## Stored records

`nix-secrets.toml` has these tables:

- `secrets`, keyed by identifier, with `format_version` (1), `version_id`
  (16 bytes, base64), `recipient_refs` or `recipient_ids`, `age_ciphertext`
  (base64) and an optional plaintext `public_key`.
- `recipient_registry`, mapping references such as `primary#0` to key
  identities.
- `public_info`, keyed by shared ID, with `version_id` and a plaintext `value`.
- `generated_public_keys`, keyed by identifier, with `version_id` and
  `public_key`.

The age plaintext is `NIXSECRT`, the byte `1`, a 2-byte big-endian identifier
length, the identifier (at most 4096 bytes), the 16-byte version and the value
(at most 16 MiB). The frontend encrypts with one `--recipient` per declared
`ssh-ed25519` or `ssh-rsa` key. Decryption fails unless the requested
identifier equals the TOML key and the inner identifier, and the outer and
inner versions match.

The backend writes the whole file under an advisory lock and replaces it
atomically. Conditional updates (`SetIfVersion`, `RemoveIfVersion` and the
public-key and public-info variants) fail if the version changed. The backend
never decrypts.

## Commits

`Commit { options, forward_agent }` commits only `nix-secrets.toml` and
`nix-secrets-profiles.toml`, and refuses while other paths are staged. With
`forward_agent`, the backend relays git's agent messages to the TUI as
`AgentRequest` and `AgentReply` (at most 256 KiB each). Only
`REQUEST_IDENTITIES` and SSHSIG `SIGN_REQUEST`s in the `git` namespace pass.

## Deployment transport

The TUI opens an SSH session to `deployment.destination`. With a remote
backend it tunnels through its existing SSH connection and does not fall back
to a direct connection. It still scans the host key directly and aborts if any
key differs from the tunneled one. It warns if the direct scan reaches no
address.

The forwarder account's authorized keys force the command
`nix-secrets-forward-deployer`, and its shell refuses any other command. The
session carries frames of `NSF1`, a kind byte, a 4-byte big-endian length and
at most 16 MiB of payload. The kinds are 1 (open manager), 2 (open deployer),
3 (data), 4 (close) and 5 (failure). The first frame must be an empty open
frame. The receiver connects to `/run/nix-secrets/deployer.sock`, sends an
empty data frame, and then relays data frames both ways. Close ends each
direction.

## Deployment messages

Inside the relayed stream each message is a 4-byte big-endian length and JSON
of at most 64 MiB.

1. The TUI sends `{ identifiers, task_identifiers }`.
2. The target answers with its state for exactly those leaves, taken from its
   own manifest: `protocol_version`, `hostname`, and per leaf the identifier,
   recipient IDs, destination, current version, generator description and
   derivation description. The TUI aborts on any field that differs from its
   own evaluation, and on missing, extra or duplicate leaves.
3. The operator approves. The TUI decrypts and sends the batch: `version`,
   `requested_identifiers`, `entries` (`identifier`, `version_id`,
   `contents_base64`), `requested_tasks`, `tasks`, `generate` and `derive`.
4. The target validates everything again, stages the whole generation on the
   destination filesystem, syncs it and switches `.current` atomically. Any
   failure keeps the previous generation.
5. The target answers `{"status": "applied", versions, generated_public_keys,
   generated_records, not_deployed}` or `{"status": "rejected", message}`.

The receiver accepts batch versions 1 to 4. Version 2 adds target generation.
Version 3 adds shared sources and `tomlPath`. Version 4 lets the batch request
a subset of the selection, adds `not_deployed`, and allows public information
with several hosts or key lines. The TUI lists values that need a newer
receiver as not deployed.

The target rejects absolute path components, `..`, symlinks, hard-link
substitution, device nodes and unexpected owners.

## Target generation

A `generate` entry has `identifier` and 32 bytes from the TUI's CSPRNG in
`client_contribution_base64`. Its identifier is in `requested_identifiers` and
not in `entries`. The TUI sends one only if the target's generator description
equals its own.

If the target already has the value installed, it re-encrypts it under the
installed version and marks the record `adopted`. Otherwise it writes the
contribution to `/dev/urandom`, generates the value from kernel randomness and
picks a new 16-byte version. It encrypts with the same inner payload to the
recipients in its manifest. The result has exactly one `generated_records`
entry per `generate` entry, with `format_version`, `version_id_base64`,
`recipient_ids`, `age_ciphertext_base64` and `adopted`.

The TUI checks each record without decrypting. The age v1 header must hold
exactly one `ssh-ed25519` or `ssh-rsa` stanza per declared recipient, matched
by key tag, and nothing else. It stores the record only if the leaf is still
unset. A lost record is recovered by deploying again, because the target
adopts the installed value.

## Derived values

A derived leaf is deployed as `prefix + source + suffix`. Its version is `d-`
and the first 16 bytes, in hex, of SHA-256 over the length-prefixed (8-byte
big-endian) source version, source identifier, prefix and suffix. A non-empty
`tomlPath`, joined with NUL, and `encoding:<encoding>` are appended in the same
way when present.

If the source is generated in the same batch, the TUI names the derived leaf in
`derive` and the target frames it. A `derive` entry whose source is not
generated in the batch is rejected.

A `generate` entry with `shared = { generator, recipient_ids,
recipient_public_keys }` is a source owned by another host. The target accepts
it only if a requested `derive` leaf uses it. It generates and encrypts the
value, installs nothing for it and returns its record.

## Deployment requests

`RequestDeployment { target, allow_partial, procedure }` queues every
deployable leaf and task of `target` and answers `DeploymentRequested`. A TUI
claims it from the approval broker, and the requester polls `ApprovalStatus`.
The TUI ignores `allow_partial` and always lists missing values as skipped.

## Secret requests

A TUI sends `AttachOperator` on its own connection and receives
`OperatorAttached`, a `ProcedureUpdate` per live procedure and
`ProceduresListed { ids }`. It then receives `Heartbeat`,
`SecretRequested { request }`, `SecretRequestWithdrawn { request_id }`,
`ProcedureUpdate` and `ProcedureEnded { id }`, and may send
`AnswerSecretRequest` and `CancelCountdown { request_id }` at any time. Any
other frame detaches it. Answers are matched by request id and count once.

`RequestSecrets { identifiers, procedure, progress, reason }` names 1 to 256
distinct identifiers. The backend fills in the requester and its parent from
`/proc/<pid>`, with the PID from `SO_PEERCRED`. At most 16 requests wait at
once. A request waits for an attached TUI and goes to the most recently
attached one. If that TUI detaches, the request keeps its id and goes to the
next one. With `progress`, the requester receives `WaitingForOperator`,
`Heartbeat` every 30 seconds and `CountdownCancelled` before the answer.

The TUI denies a request after 120 seconds unless it is a later procedure step
or the operator cancels the countdown. For the same requests the backend gives
up 610 seconds after a TUI received the request, unless it got
`CancelCountdown`.

The answer is `AnswerSecretRequest { request_id, answer }`, where `answer` is
tagged `"answer"`: `approved { values }`, `signed`, `artifacts-signed`,
`closure-signed` or `denied { reason }`. On approval the backend checks that
exactly the requested identifiers came back, binds `session.sock` (0600) in a
new 0700 directory under `$XDG_RUNTIME_DIR` and answers
`SecretSession { socket }`.

The session socket uses the same framing. It answers only same-UID
descendants of the requester. The request is
`{"operation": "get", "identifier": ...}` and the response is
`{"status": "value", "value_base64": ...}` or `{"status": "error", "message":
...}`. `EndSecretSession` or a disconnect removes the socket and erases the
values, and the backend answers `SecretSessionEnded`.

## Procedures

`BeginProcedure { title, steps }` returns `ProcedureBegun { id, token }`. The
title is at most 256 bytes with control characters removed. `steps` is 1 to
1000. The token is `id:secret`, with 32 random bytes as hex. At most 64
procedures live at once. The connecting process owns the procedure, and it
ends with `EndProcedure` or when that connection closes.

A request joins a procedure by carrying the token in `procedure`. The backend
compares the secret in constant time and requires the requester to be the
owner or its descendant. Each accepted request becomes the next step,
`ProcedureStep { id, title, step, steps, label, deployment }`. `SubmitApproval`
requests never carry a step.

## Storage Box tasks

A task entry has `identifier`, `version_id`, `password_base64` and 32 bytes in
`client_contribution_base64`. Local SSH key tasks send no password. The target
rejects an entry whose type, identifier, version, recipients, output or
bootstrap differs from its manifest. It writes the contribution to
`/dev/urandom` without `RNDADDENTROPY`, then generates the key.

The Storage Box update follows [Storage Box bootstrap](STORAGE-BOX-BOOTSTRAP.md).
Passwords and contributions never enter a generation.

## SSH signatures

`RequestSshSignature { request, reason, procedure, progress }` reaches the TUI
as a `SecretRequested` with `ssh_signature` set. Backend and TUI both require
the selected Ed25519 key, zero flags, an SSH user-authentication request for
the selected user with the `publickey` method, and no trailing bytes.
OpenSSH host-bound publickey requests are accepted if they contain a valid host
key. The TUI signs with its own agent and answers `signed { reply }`. The
requester receives `SshSignature { reply }`.

## Artifact signing

`RequestArtifactSignatures` registers read-only regular store files under one
request ID. `ReadSigningArtifact` reads 1 MiB chunks by ID, role and offset.
The registration ends on completion, rejection, timeout or requester
disconnect. The TUI hashes the streamed bytes and binds approval to the host,
signing identifier, public key SHA-256, and each role, SHA-512 and size. Only
an `artifacts-signed` answer is accepted. NMBLSIG1 signatures authenticate the
digest and role. Size is checked separately.

## Closure signing

`RequestClosureSignatures` carries a host-scoped request and a version 1
manifest whose `paths` entries have `path`, `narHash`, `narSize` and sorted
unique `references`. Limits are 4 MiB, 4096 paths and 4096 references per path.
The TUI rebuilds each Nix fingerprint, checks that the requester is alive, and
returns detached Ed25519 signatures for the requested paths.
