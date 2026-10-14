# Commands

These commands run on the machine with the repository. They accept
`--repository PATH`, which defaults to the working directory, and
`--backend-socket PATH`. Without `--backend-socket` they start the repository's
backend if none is running.

Each request waits until a TUI is attached and the operator answers it. A
request for values or signatures is denied 120 seconds after the TUI shows it,
unless the operator cancels that countdown. Inside a procedure only the first
step has a countdown. Deployment requests have none.

The TUI rings the bell and raises a desktop notification for each new request,
when a countdown starts, 30 seconds before it denies and when a procedure step
times out or fails. kitty gets OSC 99; foot, WezTerm, Ghostty and Konsole get
OSC 777; iTerm2 gets OSC 9. Inside tmux these pass only with
`allow-passthrough on`. GNOME Console and GNOME Terminal show none of these,
so there, in tmux without passthrough and in unknown terminals, the TUI calls
`org.freedesktop.Notifications` on the session bus itself, but only in a local
graphical session and never over SSH. Set
`NIX_SECRETS_DESKTOP_NOTIFICATIONS=off` to turn that off, or `=always` to use
it in addition to the terminal's notification.

## deploy

```text
nix-secrets deploy [--wait] HOST
```

Queues a deployment of every deployable leaf of HOST. Without `--wait`, it
exits once the request is queued. With `--wait`, it exits non-zero if the
operator rejects the deployment or it fails. `--allow-partial` is accepted and
has no effect, because missing values are always skipped and listed.

## quarantine

```sh
nix-secrets quarantine list
nix-secrets quarantine adopt ID
nix-secrets quarantine discard ID
```

A host may return a value the schema does not accept: a generated record
nobody requested or encrypted to other recipients, one that lost a race with
a value you entered, or a public key outside the approved tasks. Each is kept
in the store's `quarantine` table with its source host, deployment, time and
reason, never deployed, and shown in red in the TUI. `adopt` checks the value
against the current schema and stores it only where nothing is stored yet.
`discard` deletes it.

## procedure

```text
nix-secrets procedure --title TEXT [--steps N] -- COMMAND [ARGUMENT ...]
```

Runs COMMAND. Every request that COMMAND or its descendants make becomes a
numbered step of one approval dialog titled TEXT. Repeated SSH logins to the
same destination, one after another, are one step. `--steps` sets the total
shown in `step 2/4`. Between steps the dialog lists the finished steps and
waits for the next one. After the last step, or when COMMAND exits, it shows
the result and the exit status. COMMAND receives the token in `NIX_SECRETS_PROCEDURE`.
The command exits with COMMAND's status. If no backend is reachable, COMMAND
still runs and its requests appear one by one.

```text
nix-secrets procedure-step-failed --label TEXT --reason TEXT
```

Run inside COMMAND, reports that the step TEXT failed. The dialog lists it
with ✗, its position and the reason, and the result names it, also after
COMMAND exits, until the operator closes it. A second report with the same
label right after updates that step, so "rolling back" can become "rolled
back". A later request starts a new step. The command prints
`nix-secrets: step failed: LABEL: REASON` to stderr. Outside a procedure or
without a running backend it notes that the TUI was not reached and exits 0.
It waits at most 5 seconds for the backend. It exits 1 if the backend
refuses the report. It never starts a backend.

```text
nix-secrets procedure-step-warning --label TEXT --reason TEXT
```

Reports that the step TEXT worked with a caveat, the same way. The dialog
lists it with ⚠ and keeps it after later steps. A procedure that exits 0 with
warnings shows "succeeded with warnings" and stays until the operator closes
it with Enter. A clean success closes on its own. The command prints
`nix-secrets: step warning: LABEL: REASON` to stderr.

## with-secrets and pipe-secret

```text
nix-secrets with-secrets [--reason TEXT] IDENTIFIER... -- COMMAND [ARGUMENT ...]
nix-secrets pipe-secret [--reason TEXT] IDENTIFIER [-- COMMAND [ARGUMENT ...]]
```

`with-secrets` asks once for up to 256 values. After approval it runs COMMAND
with `NIX_SECRETS_SESSION` set. Descendants of COMMAND can then read those
values with `pipe-secret` without another prompt. Other identifiers are
refused. It exits with COMMAND's status. On denial COMMAND does not run.

`pipe-secret` writes one value to COMMAND's stdin. Without a command it writes
the value to stdout, which must not be a terminal. Outside a session it asks
for that one value.

`--reason` is shown to the operator as unvalidated text of at most 4096 bytes.
Operator keys declared `signingOnly = true` are never released.

```sh
nix-secrets with-secrets HOST.services.signing.private-key \
  --reason 'Sign this release.' -- release-script
# Inside release-script:
nix-secrets pipe-secret HOST.services.signing.private-key -- signer --key-stdin
```

Approved plaintext is then in backend memory and in COMMAND. See the
[threat model](THREAT-MODEL.md#secret-requests).

`--local` decrypts in the calling process without the TUI. Use
`--secret-identity PATH` or 1Password. `--1password-shared-session` reuses the
terminal's 1Password authorization. `--schema-file PATH` reads the schema from
a file and requires `--backend-socket`.

## with-ssh-agent and approve-ssh-login

```sh
nix-secrets with-ssh-agent --public-key ./login.pub \
  --destination operator@host.example --reason 'Run maintenance.' -- \
  ssh -o IdentityAgent=SSH_AUTH_SOCK -o IdentitiesOnly=yes -i ./login.pub \
  -o StrictHostKeyChecking=yes operator@host.example maintenance-command
```

Runs COMMAND with a temporary agent that offers only the given Ed25519 key.
The operator approves the SSH logins to the destination before COMMAND
starts. The TUI then starts a signer detached from its terminal, and the
signer asks the client agent once, so 1Password asks right away. Only after
that does COMMAND start, and its logins are signed without asking anyone.
Nothing waits for a person while a server counts its LoginGraceTime.

The approval lasts 30 minutes and 256 signatures, and ends when COMMAND
exits. A login without a live approval is refused. The agent signs only SSH
user authentication for that key and user, and only for COMMAND and its
descendants. Nothing checks the host name, so the SSH client must verify the
host key.

With `--approve-on-request`, COMMAND starts at once and asks for the approval
itself, right before it connects:

```text
nix-secrets approve-ssh-login
```

It exits zero once the operator approved, or at once while an earlier
approval has more than two minutes and one signature left. Run it before
every connection that needs a signature; it asks again only when the
approval ran out.

## sign-artifacts

```text
nix-secrets sign-artifacts --host HOST --reason TEXT IDENTIFIER < manifest.json
```

Reads a JSON object of at most 64 KiB with an `artifacts` array. Each entry has
`role`, `path`, lowercase `sha512` and `size`. The roles `generation-image`,
`boot-config`, `gen-kernel`, `gen-initrd` and `rescue-sfs` are required.
`network-stage` and `rescue-tools` are optional. The TUI streams and hashes
the store files, and after approval its signer produces detached signatures.
The output has a `signatures` array with the same role, digest and size plus
`signature_base64`. The caller must reject missing or changed entries.

The TUI runs the signer named by `NIX_SECRETS_ARTIFACT_SIGNER` in its own
environment. A request cannot choose another signer.

## sign-closure

```text
nix-secrets sign-closure --host HOST --reason TEXT IDENTIFIER
```

Reads version 1 closure metadata from stdin and writes standard Nix Ed25519
signatures to stdout. The TUI signs what the requester claims and does not
check NAR contents.

Both signing commands need an operator leaf with `signingOnly = true`. Neither
has a local mode, and the private key stays in the TUI.
