# Protocol

This document defines component boundaries and message flow. Wire messages are
versioned, length-delimited, and size-limited. The receiver rejects unknown
versions, fields that change security meaning, duplicate map keys, malformed
paths, and trailing data.

## Components

- The TUI evaluates the repository, accepts user input, encrypts and decrypts
  values, asks for deployment consent, and authenticates the final SSH target.
- The backend coordinates frontends and manages `nix-secrets.toml` with atomic
  writes. It stores ciphertext and public metadata. An approved secret request
  also places the requested plaintext in backend memory for the lifetime of the
  command.
- The deployment relay carries a byte stream between the TUI and the target.
  It does not terminate the target SSH session.
- The target receiver validates its requirements and atomically installs the
  selected secret generation.
- The readiness waiter checks declared paths by metadata and does not open
  secret files. Only consuming units depend on it.

## Command grammar

```text
nix-secrets [SSH_ARG ...] -- REPOSITORY
```

An empty `SSH_ARG` sequence selects a local repository. Otherwise the program
passes the sequence to OpenSSH as individual arguments. `REPOSITORY` is exactly
one argument after `--`.

```console
nix-secrets -- ~/config
nix-secrets -p 222 admin@example.net -- ~/config
```

The program does not concatenate arguments into a shell command. Remote
startup invokes a fixed backend command with a framed protocol. The backend
expands a leading `~/` to the remote account's home directory. It rejects
other tilde forms, NUL bytes, and paths outside the selected repository.

## Evaluation

The TUI and the target read a canonical JSON result from a fixed flake output.
Its outer shape is:

```text
<hostname>.<services|user-{user}-services>.<service>.<service-defined structure>
```

A leaf definition includes a stable path identifier, a recipient identifier,
the target category (`setup`, `service`, or `backup`), ownership, mode, and
applicable limits. Any level of the tree may set defaults that lower levels
inherit, but evaluation must resolve every leaf before it reaches the protocol.

The evaluation result contains only public configuration: secret identifiers,
recipients, destinations, ownership, modes, and consumers. Secret values stay
in the encrypted TOML store until the TUI decrypts them.

For deployment, the frontend compares every selected leaf from its fresh
evaluation with the target's generated manifest. The comparison covers
identifier, recipients, destination, owner, group, mode, and consumers.

## Local backend discovery

The frontend tries the configured socket path first. The default is:

```text
$XDG_RUNTIME_DIR/nix-secrets/<repository-id>.sock
```

Before protocol negotiation, each side obtains Unix peer credentials from the
kernel. A side accepts the connection only when the peer's effective UID is the
expected repository user. A stale socket, wrong owner, non-socket node, or
unexpected peer causes failure.

If no valid backend exists, the frontend starts one through a fixed `nix run`
application. It passes the repository and evaluated configuration as distinct
arguments or framed input. The backend publishes its socket only after it is
ready. When several frontends start a backend at once, they all end up using
the one process that binds the socket.

Requester commands start the backend the same way when none runs. These are
`with-secrets`, `pipe-secret`, `with-ssh-agent`, `sign-artifacts`,
`sign-closure`, `deploy`, and `procedure`. They use the same versioned socket,
`backend-v<version>-<repository hash>.sock`, and its `.lock`. A backend that a
requester started and one that the TUI started are therefore the same process.
The requester's request then waits until an operator attaches. A starter never
removes the socket of a backend that holds the lock. This holds even while that
backend still evaluates or does not answer a probe. The starter waits for it
instead. A backend whose socket was removed or replaced exits and releases the
lock, so it can never block later starts.

`GetSchema` returns the schema document the backend evaluated, its age, and
whether requests wait for an operator. The TUI uses this document instead of
evaluating the repository itself when requests wait or when the evaluation is
at most two minutes old. An operator who opens the TUI for a waiting request
therefore sees it at once.


## Stored record

`nix-secrets.toml` maps stable schema paths to records. Each record contains:

- an opaque random version identifier;
- the public recipient fingerprints or key identifiers;
- one base64-encoded complete age ciphertext.

The canonical full schema path is the secret identifier. Lookup, schema
resolution, recipient selection, and destination resolution use only this
identifier. The opaque version ID is revision metadata and plays no part in
those decisions.

The configured SSH public keys stay in the Nix schema as plaintext metadata.
The TOML record does not encrypt or duplicate them. The record contains no SSH
private key.

To encrypt, the frontend runs `age --encrypt` with one `--recipient` argument
for every configured SSH public key. It writes the complete plaintext payload
to stdin and reads the complete age file from stdout. The compact payload
contains a fixed tag and format version, the canonical identifier, the opaque
version ID, and the raw secret bytes. Age authenticates all of it.

On decryption, the requested identifier must equal both the outer TOML map key
and the authenticated inner identifier. The outer and authenticated inner
version IDs must also match. A mismatch rejects the whole record. Replacing a
value at the same identifier generates a new opaque version and ciphertext.
The new record stays compatible with the same schema leaf, recipients, and
destination.

## Editing flow

1. The TUI obtains the resolved manifest and the current encrypted records.
2. It displays each leaf as `set` or `unset`, based only on whether a record
   exists.
3. Enter accepts masked input. Paste on a selected leaf accepts clipboard
   input. Replacing a value requires confirmation.
4. The TUI sends the secret to age through a pipe and zeroizes its plaintext
   buffer after use.
5. The backend validates the leaf, record size, and recipient IDs. It does not
   decrypt the age ciphertext.
6. The backend locks, writes, synchronizes, and atomically replaces
   `nix-secrets.toml`. Other frontends see the update on their next read.

The backend serializes updates under an advisory lock and atomically replaces
the complete TOML store. It stores named recipients as versioned references
such as `primary#0`. One top-level registry holds the corresponding key
identity. Existing records with inline `recipient_ids` remain readable.
Rotating a named key adds a new registry revision and leaves old records
unchanged. A stored OpenSSH private-key record carries the derived public key
as plaintext metadata next to the ciphertext. For a target-generated key, the
frontend registers the public half the target returns through a version-checked
update and read-back. A retry reuses an existing target private key.

Public-info leaves use a separate plaintext TOML table keyed by stable
`sharedPublicId`. Their updates and deletions use compare-and-set. The operator
still requests deployment for a whole target, and the target attests it
against the Nix manifest. The privileged target validates the exact known-hosts
host, port, Ed25519 key, destination, ownership, and mode before it publishes a
world-readable file in `/persistent/public-info`. These values do not enter
secret readiness gates.

## Commits

`CommitSummary` returns the diff stat and status of `nix-secrets.toml` and
`nix-secrets-profiles.toml`, the other staged paths, the message of `HEAD`,
and whether `commit.gpgsign` is set. `Commit { options, forward_agent }`
stages and commits only those two files. It refuses while other paths are
staged. With `forward_agent`, the backend serves a temporary agent socket
(0600, in a 0700 directory under `$XDG_RUNTIME_DIR`, same-UID peers only) to
`git -c gpg.ssh.program=ssh-keygen`. It forwards each agent message to the
frontend as `AgentRequest { message }`. The frontend answers with
`AgentReply { message }` from its own agent. Both sides pass only
`REQUEST_IDENTITIES`, and `SIGN_REQUEST` over an SSHSIG blob in the `git`
namespace. Every other message gets `SSH_AGENT_FAILURE`. The exchange ends with
`Committed { result }`, or with `Error { message }` carrying git's stderr. Agent
messages are limited to 256 KiB. Adding these requests raised the backend
compatibility version to 9.

## Deployment transport

The frontend authenticates an SSH session to the final target. With a remote
backend, the frontend's existing SSH master forwards target TCP connections.
The frontend checks the original target's host key and decrypts locally. If the
master connection is lost, deployment stops. The frontend does not reconnect
and does not fall back to a direct connection to the target. The additional
direct host-key probe resolves the target on the client. It probes every A and
AAAA address separately and names the address family explicitly. Each address
gets three seconds, within a total budget of ten seconds. An address without a
route fails at once. If the name does not resolve, the frontend probes the name
once per family within three seconds. If no address is reachable, the frontend
warns. If any key it observes differs from the tunneled endpoint's key, it
aborts before target authentication or secret transmission.

The frontend uses the user's OpenSSH host-key policy and `known_hosts` files.
A changed key aborts. For an unknown key, the UI shows the presented key and
lists known hostnames already associated with it, then asks for an explicit
decision.

SSH-agent keys may authenticate either SSH hop. Recipient decryption uses
`age --decrypt -j 1p` instead. With it, `age-plugin-1p` obtains the matching
private key from 1Password through `op`. 1Password can then authorize access
with no key file in the repository or the frontend configuration. This path is
separate from the SSH-agent signing protocol.

## Deployment flow

0. Before anything authenticates, the TUI scans the target's host key without
   logging in. It then shows step 1. For an unknown key, step 1 asks the
   operator to trust it. For a known key, step 1 names the forwarder key the
   TUI will log in with. The TUI logs in only after the operator approves that
   step, and only then does the SSH agent (1Password) ask to sign. If the agent
   refuses, the error says that the agent refused. It does not blame the
   target's authorized keys.
1. The frontend sends a bounded selection of canonical leaf identifiers.
2. The target resolves that selection only from its generated Nix-store
   manifest. It returns the exact public leaf metadata and the current opaque
   versions. The frontend compares every field with its fresh evaluation. Any
   extra, duplicate, differently configured, or unresolved leaf aborts.
3. The TUI presents one modal. It lists the target, the leaves, whether each
   leaf is created or replaced, and the SSH recipient identities required to
   decrypt them.
4. After approval, the TUI invokes the 1Password-backed provider. On rejection
   or unlock failure the modal stays open for a retry, and the TUI sends no
   plaintext.
5. The TUI decrypts locally. It sends each leaf, its stable identifier, and its
   opaque version inside the end-to-end SSH channel.
6. The target validates identifiers, paths, sizes, ownership, permissions,
   completeness, and the exact selected set on its own.
7. The target stages the whole generation on the persistent destination
   filesystem, writes with restrictive permissions, synchronizes it, and
   publishes it atomically. Any failure keeps the previous generation.
8. The target reports only success or a structured error. It erases transient
   plaintext buffers as far as its memory-safe language and library interfaces
   allow.

The final layout is:

```text
/persistent/secrets/<service>/<setup|service|backup>/<secret>
```

Path components come from the validated manifest. The target rejects absolute
components, `..`, symlink traversal, hard-link substitution, device nodes, and
unexpected owners.

## Operator-initiated deployment

`RequestDeployment { target, allow_partial, procedure }` asks the backend to
queue a deployment of every deployable leaf of `target` in its evaluated
schema. That set is every stored leaf, including public information and derived
leaves, and every generated-secret task. Operator-only leaves are left out. If
the request carries a procedure token, it becomes the next step of that
procedure, as described in Procedures. The backend picks a random request id,
submits `ApprovalRequest { id, target, secrets,
allow_partial }` to the approval broker, publishes `ApprovalRequested`, and
answers `DeploymentRequested { request }`. If no frontend is registered, the
backend still queues the request. A frontend that registers later is offered
it at once. Nothing happens to the target until a TUI claims the request and
its operator approves it. Registered TUIs claim it like any approval, so the
deployment flow above applies unchanged. The requester then tracks it with
`ApprovalStatus`. `ResolveApproval` carries an optional `message`. The frontend
fills it with the deployment summary or the reason for refusing. `Resolved`
reports it to the requester.

`allow_partial` is the requester's proposal, and the operator can toggle it in
the dialog. When it is set and the only missing values are derived values whose
source is unset on another host, the frontend leaves those values out of the
target selection, so the target keeps waiting for them. The summary lists them
as skipped. Any other missing value still refuses the whole deployment. Adding
these requests raised the backend compatibility version to 11.

## Values generated at deployment

Deployment protocol 2 lets the target generate stored values that are unset
in the operator store. The plaintext of such a value stays on the target.

1. Before connecting, the frontend classifies each requested unset leaf. A
   leaf is generatable when it is not public information, not
   `externalInputRequired`, not `generateOnDeploy = false`, and either has
   `valueType = "password"` (password generator under its consumer
   constraints) or declares `valueGenerator`. A Storage Box task whose
   bootstrap input is unset is never generatable. If any requested value is
   not generatable, the frontend refuses the whole deployment with one list of
   all such values. It generates, sends, and writes nothing. The approval
   dialog shows the same list, or the values the target will generate.
2. The target's state reports a canonical `generator` description for each
   stored leaf, derived from the target's own manifest. Before sending a
   generation request, the frontend requires this description to equal the one
   derived from its schema. The target therefore cannot produce a value in
   another format.
3. The batch carries `generate` entries. Each has an identifier and 32 bytes
   from the frontend CSPRNG. Their identifiers are part of
   `requested_identifiers` and cannot also appear in `entries`.
4. If the target already has a nix-secrets version of the leaf installed, it
   re-encrypts that installed value under its installed version (`adopted`).
   Otherwise it writes the contribution to `/dev/urandom`, generates the value
   from kernel randomness, and chooses a fresh 16-byte version. It encrypts
   the value with the same inner envelope as the frontend, with identifier and
   version authenticated inside the age payload. It encrypts to the leaf's
   recipient keys from its manifest, with the receiver's pinned `age`.
5. The target stages and publishes the value with the rest of the generation.
   The result carries `generated_records`, exactly one per requested
   identifier. Each holds the format version, version, recipient IDs, and age
   ciphertext.
6. The frontend checks each record without decrypting it. It checks the format
   version, the 16-byte version, that the recipient IDs equal the schema's, and
   the age v1 header. The header must contain exactly one `ssh-ed25519` or
   `ssh-rsa` stanza per schema recipient key, matched by age's SHA-256 key tag,
   and no other stanzas. The frontend stores the record with a conditional
   write that requires the value to be still unset. The write also publishes
   the normal change event.

Retry behaviour: a record can be lost between target publication and the store
write, for example through connection loss or backend failure. Deploying again
recovers it, because the target adopts the installed value and does not
generate a different one. If someone entered the value in the store in the
meantime, the conditional write keeps that value, the frontend reports it, and
the next deployment installs it.

## Derived values

A stored leaf with `derivedFrom = { identifier; prefix; suffix; }` is never
stored or generated. The frontend decrypts the named source, which may belong
to another host, and deploys `prefix + source + suffix` as an ordinary entry.
Its version is `d-` followed by 32 hex digits of SHA-256 over the
length-prefixed source version, source identifier, prefix, and suffix. The
version changes exactly when the source value or the framing changes.

If the source is unset and in the same deployment's `generate` list, it is on
the same target. The batch then names the derived value in `derive` and does
not send it. The target frames it from the value it generated or adopted for
the source and computes the same version. Every target secret reports its
canonical `derived` description. The frontend compares it with its schema
before deploying, so the target frames exactly as declared. The target rejects
a `derive` entry whose source is not generated in the same batch.

Protocol 3 adds a shared source. A `generate` entry with `shared = {
generator, recipient_ids, recipient_public_keys }` names a stored symmetric
secret of another host, taken from the operator's schema. It is not part of
the selection or of `requested_identifiers`. The target accepts it only when a
requested `derive` value of its own is framed from it. The target generates it
fresh with that generator, encrypts it to those recipients, installs nothing
for it, and returns its record. The frontend checks the record against the
source leaf and stores it. For any other unset source, the frontend leaves the
derived value out of the selection, lists it, and deploys the rest. `tomlPath`
selects a string field of a TOML source before framing. It is hashed into the
version after the other parts, so versions without it are unchanged.

Protocol 4 lets the target leave out a target task whose prerequisite is
absent on it. One example is a Storage Box `knownHostsFile` that is neither
installed nor supplied in the same batch. The target removes the task from the
published `requested_identifiers`, and `Applied.not_deployed` maps its
identifier to the reason, which names the path. The target publishes
everything else in the batch. Public information may carry several known_hosts
lines for any of the leaf's hosts, with Ed25519, ECDSA, or RSA keys. Its
attestation lists them in `expected_ssh_hosts` and omits the field when it is
empty. Public information supplied in a batch is visible to that batch's tasks
before publication. Every target I/O error names the step and the path.

## Operator-only values

A `kind = "operator"` leaf has recipients but no destination. The Nix module
removes it from every host manifest and readiness waiter. The frontend refuses
any deployment request that names it before connecting. Its stored record may
carry `public_key`, the base64 of the public key its declared generator wrote
to file descriptor 3. The generator runs on the operator's machine as
`nix run INSTALLABLE -- ARGS…` with stdin from `/dev/null`. It writes the
private key to stdout (at most 1 MiB) and the public key to fd 3 (at most
64 KiB). The frontend encrypts the private key before storing it. Neither half
is written to disk.

`nix-secrets pipe-secret ID [-- COMMAND…]` writes one stored value to the
command's stdin, or to stdout when stdout is not a terminal. The section Secret
requests describes where the value comes from.

## Secret requests

A process on the backend host obtains plaintext only through the operator's
TUI, which decrypts and returns it after the operator approves.

1. The TUI opens a dedicated connection and sends `AttachOperator`. The
   backend answers `OperatorAttached`. It then sends a `ProcedureUpdate
   { procedure }` for every live procedure. After that it sends `Heartbeat`,
   `SecretRequested { request }`, `SecretRequestWithdrawn { request_id }`,
   `ProcedureUpdate`, and `ProcedureEnded { id }` frames. The TUI may send
   `AnswerSecretRequest` and `CancelCountdown { request_id }` frames at any
   time. Any other frame, or a hang-up, detaches it. Several requests can wait
   on one channel at once. The TUI answers each by its id, in any order. An
   answer counts once, and only for a request that still waits. A replay, an
   answer to a withdrawn request, or a made-up id reaches nobody.
2. `nix-secrets with-secrets ID… -- CMD…` connects to the repository's
   backend socket. If no backend runs, it starts one, as described in Local
   backend discovery. It sends `RequestSecrets { identifiers, procedure,
   progress }` with 1 to 256 distinct canonical identifiers. As on every
   connection, only same-UID peers are accepted. `procedure` carries the token
   from `NIX_SECRETS_PROCEDURE` when the requester runs inside `nix-secrets
   procedure`, as described in Procedures. With `progress`, the requester also
   reads `Heartbeat` frames every 30 seconds and one `CountdownCancelled` frame
   before its answer. A requester that does not set `progress` gets exactly one
   answer frame, as before.
3. The backend fills `request.requester` and `request.parent` from
   `/proc/<peer pid>` (PID from `SO_PEERCRED`; executable, argv, cwd), and
   never from the request. It forwards the request to the most recently
   attached TUI. Up to 16 requests from all requesters can wait for the
   operator at once, and the backend refuses another one immediately. Without
   an attached TUI, the request waits for one. A requester with `progress`
   gets one `WaitingForOperator` frame and then heartbeats. Nothing counts
   down until a TUI receives the request. If that TUI detaches before it
   answers, the request waits for the next TUI, which shows it again from the
   start. The backend withdraws a request when its requester disconnects or
   when the backend gives up on it. The TUI then drops the prompt, and the
   request is denied.
4. The TUI rejects undeclared, public-info, and unset identifiers without
   asking. Otherwise it shows a modal. The modal shows each value's
   identifier, kind, and description, its recipient names and SSH key
   fingerprints, the decryption identity (1Password or an identity file), and
   the requester and its parent. Only Ctrl+Shift+Y or the Yes button approves.
   n, Enter, and Esc deny. A request outside a procedure, or the first step of
   one, also shows a 120-second countdown and is denied when it runs out.
   Later steps of a procedure have no countdown. The operator can cancel the
   countdown with c or the "Keep waiting" button. The TUI then sends
   `CancelCountdown`. The backend stops its own deadline for that request,
   which otherwise is 610 seconds and bounds a TUI that stopped answering. It
   sends `CountdownCancelled` to a requester with `progress`. The CLIs print
   "operator cancelled the auto-reject countdown; waiting" and keep waiting. A
   request without a countdown waits until the operator answers it or the TUI
   or the requester disconnects.
5. On approval, the TUI decrypts every value in one provider batch. The
   `nix-secrets-1password --batch` launcher authorizes once and runs age once
   per ciphertext inside that authorization. The TUI answers
   `AnswerSecretRequest { request_id, answer: approved { values } }`, or
   `denied { reason }`. The values travel only on this connection, which is
   the authenticated channel between the TUI and the backend. For a remote
   backend it runs through the TUI's SSH tunnel.
6. The backend checks that exactly the requested identifiers came back. It
   binds `session.sock` (0600) in a new 0700 directory under
   `$XDG_RUNTIME_DIR` and answers `SecretSession { socket }`. It keeps the
   values only in memory.
7. `with-secrets` runs `CMD` with `NIX_SECRETS_SESSION=<socket>`. The backend
   answers a connection to the session socket only for a same-UID peer whose
   process descends from the requester. The peer sends
   `{"operation":"get","identifier":…}` and receives
   `{"status":"value","value_base64":…}` or an error. The backend refuses an
   identifier outside the approved batch. The session never asks the operator
   again.
8. When `CMD` exits, `with-secrets` sends `EndSecretSession`. A disconnect has
   the same effect. The backend removes the socket and directory, erases the
   values, and answers `SecretSessionEnded`. `with-secrets` exits with `CMD`'s
   status. On denial, timeout, or failure, `CMD` never runs.

`pipe-secret ID` reads from `NIX_SECRETS_SESSION` when it is set. Otherwise it
sends a `RequestSecrets` with one identifier, reads the value from the session,
and ends the session. `--local` keeps the earlier behaviour of decrypting in
the calling process. `with-secrets --local` serves such a batch from its own
process with the same session protocol. Adding these requests raised the
backend compatibility version to 10.

## Procedures

A procedure groups the operator prompts of one logical operation. An update
run is an example: it authenticates over SSH, signs a closure, and then
deploys secrets. The TUI shows all of these prompts in one dialog under a
common title.

1. `nix-secrets procedure --title TITLE [--steps N] -- CMD…` connects to the
   repository's backend and sends `BeginProcedure { title, steps }`. The
   backend removes control characters from the title. It records the
   procedure with the connecting process as its owner, using the PID from
   `SO_PEERCRED`. It answers `ProcedureBegun { id, token }`. The `id` is
   public. The `token` is `id:secret`, where the secret is 32 random bytes. At
   most 64 procedures live at once.
2. The command runs with `NIX_SECRETS_PROCEDURE=<token>`. Every nix-secrets
   requester it starts sends the token as `procedure` in its request. These
   requesters are `with-ssh-agent`, `with-secrets`, `pipe-secret`,
   `sign-artifacts`, `sign-closure`, and `deploy`.
3. The backend accepts a token only when its secret matches. It compares the
   secret in constant time. The requesting peer must also be the owner or one
   of its descendants by the parent chain in `/proc`. The backend refuses a
   process that does not descend from the procedure, even with the right
   token. An ended procedure refuses every token. Requests without a token
   behave as before, and each one is a procedure of one step.
4. Each accepted request becomes the next step. The backend numbers it and
   labels it from what it asks, for example "SSH authentication to
   root@ns1", "sign closure for ns1", "release 2 secret values", or "deploy
   secrets to ns1". It attaches `ProcedureStep { id, title, step, steps,
   label, deployment }` to the `SecretRequest`, or to the deployment request
   in the approval broker. `PollApprovals` reports it as
   `Approvals { requests, procedures }`. A request submitted with
   `SubmitApproval` can never carry a step. All attached TUIs also receive a
   `ProcedureUpdate` for each step. They receive `ProcedureEnded` when the
   procedure's connection sends `EndProcedure` or closes. `nix-secrets
   procedure` does this when its command exits.
5. Only step 1 counts down, as described in Secret requests. The backend
   numbers a step only once a TUI can be asked, so a refused request does not
   use one up.

A deployment in a procedure can cause public-key follow-ups. These follow-ups
join that procedure inside the TUI. The TUI remembers which deployment
submitted them, and the backend is never told.

If no backend is reachable, `nix-secrets procedure` warns and runs the command
anyway. Its prompts then appear one by one. Adding procedures raised the
backend compatibility version to 22.

In the TUI, every prompt and every deployment approval belongs to a procedure.
The foreground procedure's dialog is titled `TITLE · step N/M: LABEL`. The
body names the requester. A deployment dialog's title continues with its own
stage, as in `… › Deploy ns1 · step 2/3: choose what to deploy`. `m` minimises
the dialog into the task bar above the actions. The task bar lists every
procedure with its current step. It also shows whether the procedure waits for
the operator or is working. A click on an entry, or `M`, restores a
procedure. `M` picks flashing entries first. A procedure never takes the
screen from another dialog. A procedure that starts or asks while anything
else is open starts minimised, and its entry flashes. The terminal bell and a
desktop notification announce it once. When nothing is open, the procedure
opens directly. The operator must read a minimised host-change review again
from its top before the TUI offers Save. Secret prompts of different
procedures wait and are answered independently. The TUI claims one deployment
approval at a time. A second procedure's deployment therefore reaches the task
bar only once the operator answers the open one. Meanwhile its entry shows
"deployment queued behind the open one".

## Reconnecting

The TUI keeps working when its connection to the backend drops. This happens,
for example, when the backend restarts or the SSH tunnel to a remote backend
breaks. The status line then reads "Disconnected from the backend,
reconnecting: REASON".

- The worker connection reconnects with backoff. The delay starts at one
  second and doubles up to 30 seconds. The worker then registers as a frontend
  again. When the socket is gone, the TUI first starts the local backend again,
  or opens a new SSH tunnel to the remote one.
- The operator channel attaches again with the same backoff. The TUI closes a
  lost channel before anything can answer on it. A break therefore never
  approves or denies a request on screen. The request's prompt disappears. The
  backend keeps the request waiting and sends it again, with the same id, to
  the next TUI that attaches. That TUI shows it from the start, with a fresh
  countdown if the request counts down. A decision made while disconnected
  reaches nobody. When a TUI attaches, the backend first lists the live
  procedures with `ProceduresListed`. The TUI drops the procedures that ended
  meanwhile.
- The TUI discards a deployment dialog that was open during the break. Its
  broker claim went back to the queue with the old connection. Its prepared
  connection, displayed host-change batch, and row selection are never used
  again. The TUI tells the operator. The backend offers the request again
  under a new claim from its first step, so the operator must see and read
  every review again.
- Change notifications resume on a new subscription and refresh the tree.

A restarted backend loses its waiting requests and procedures with its
process. Their requesters fail and must run again.

## Generated-secret tasks

A generated leaf has `kind = "generated"` and a `generatedSecret` declaration
in place of a direct destination. A Storage Box task stores an encrypted
bootstrap password at its canonical identifier. That input is never
interpreted as the generated output. Local SSH key tasks need no stored input
and do not appear in the editable TUI tree. The target generates them during
deployment.

The `storage-box-ssh-key` task declares its output destination and public
bootstrap parameters: Storage Box host, port, user, and one or more complete
pinned OpenSSH host public-key lines. Selection and target-state messages keep
ordinary secrets and tasks in separate arrays. A receiver therefore cannot
silently treat a task password as file contents.

After target-state comparison and approval, a Storage Box task entry contains
the stable identifier, the ciphertext version, the password, and exactly 32
bytes from the frontend CSPRNG. A local SSH key task uses no password. Both
sides zeroize sensitive inputs and carry them only inside the authenticated
SSH stream. The receiver rejects an entry if its task type, identifier,
version, recipients, output, or bootstrap metadata differs from the
Nix-generated manifest.

The receiver writes the full frontend contribution to `/dev/urandom` with an
ordinary write before it requests target-local randomness for key generation.
It does not use `RNDADDENTROPY` and does not claim entropy credit. Tests
replace both operations with injected implementations and assert the ordering
without changing the host random pool.

The receiver connects in-process to the Storage Box, verifies the configured
host key, authenticates with the password, and updates `.ssh/authorized_keys`
over SFTP. It keeps unrelated entries and allows exactly one entry with the
stable prefix `nix-secrets:<target-host>:<task-id>:`. A retry reuses an
existing valid output key. If a crash happened after the remote update but
before local publication, the retry replaces the marked remote entry before it
publishes a new local key. Malformed or duplicate marker entries fail closed.

The receiver publishes the generated private key atomically at its declared
persistent destination, and only after remote reconciliation succeeds. Task
passwords, frontend contributions, and target seeds never enter a secret
generation.

## Readiness

The NixOS module derives the expected files from the same resolved manifest.
Once per second, the waiter checks file existence, type, owner, group, and mode
with metadata operations. Its service account cannot read secret contents.

Each consuming unit declares `Requires=` and `After=` on the waiter for its own
secret set. The module adds no global dependency to `multi-user.target`. SSH
starts without secrets, so initial deployment and repair stay possible. A
machine does not count as booted successfully while required application units
are unhealthy.

## Client SSH authentication signatures

`with-ssh-agent --public-key FILE --destination USER@HOST [--reason TEXT] -- CMD`
runs CMD with a private temporary agent. The agent lists only the selected
public key. A signing request becomes `RequestSshSignature { request, reason,
procedure, progress }`.
The backend fills in the requester and parent from kernel peer credentials and
sends a `SecretRequested` with `ssh_signature` set and no secret identifiers.

The backend and the client both validate the exact Ed25519 key, zero signing
flags, an SSH user-authentication message, the selected username, the
publickey method, and the absence of trailing bytes. They refuse Git signatures
and other agent operations. The normal Git relay keeps its own Git-only policy.

Both ordinary publickey and OpenSSH's
[host-bound publickey](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL#L319)
authentication messages are accepted. A host-bound message must include a
well-formed server host key.

The client shows an SSH authentication approval with the key name and
fingerprint, the caller identity, and the reason, marked as unvalidated. An
agent challenge does not let the client verify the claimed host. Strict SSH
host-key verification is the job of the calling SSH process. On approval the
client requests one signature from its local agent and answers
`Signed { reply }`. Only a correctly framed Ed25519 signature becomes
`SshSignature { reply }` on the requester connection. This path uses no
decryption provider, no secret session, and no private-key transfer.

The temporary agent socket is removed when the child exits. A refusal or a
missing client agent fails authentication. It never falls back to the
backend's agent.

## Detached artifact signing

Backend compatibility version 18 adds `RequestArtifactSignatures` and
`ReadSigningArtifact`. The backend pins read-only regular Nix store files for
one opaque request ID. Bounded reads name only that ID, a role, and an offset.
The registration ends on completion, rejection, timeout, or requester
disconnect.

The frontend hashes the streamed bytes itself and binds approval to the host,
the signing identifier, the public-key SHA256, and the role, SHA512, and size
of every artifact. Its locally configured trusted signer receives the key after
approval and returns NMBLSIG1 sidecars. The frontend accepts only
`ArtifactsSigned` as a successful answer and rejects plaintext answers and
other signature types. A signing-only operator leaf refuses `RequestSecrets`,
including after a schema reload.

NMBLSIG1 authenticates the artifact digest and role. The frontend checks size
against the streamed bytes and the response metadata. Size is not a separate
authenticated field in the existing sidecar format.

## Native Nix closure signing

`request-closure-signatures` carries an opaque host-scoped signing request and a
version 1 public manifest (`paths`: `path`, canonical `narHash`, `narSize`, sorted
unique `references`). The client reconstructs each standard Nix fingerprint,
approves the exact batch, checks that the requester is still alive, and signs
locally. `closure-signatures` returns only named detached Ed25519 signatures
bound to the requested paths. The limits are a 4 MiB manifest, 4096 paths, and
4096 references per path. The requester supplies this metadata, and nothing
verifies the NAR bytes independently. Signing-only operator keys reject
plaintext secret requests. The backend compatibility socket version is 20.
