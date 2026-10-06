# Command reference

## Repository and backend

```text
nix-secrets [SSH_ARG ...] -- REPOSITORY
```

With no SSH arguments, the repository is local. Otherwise OpenSSH receives the
arguments one by one, and the backend expands a leading `~/` on the remote
machine. The repository configuration chooses the backend socket. Discovery
checks that the socket peer runs as the same user. Several frontends can share
one backend.

The commands below run on the machine that holds the repository and backend.
They accept `--repository PATH`, which defaults to the working directory, and
`--backend-socket PATH`. Without `--backend-socket`, they start the repository's
backend when none runs. This is the same backend the TUI would start. A TUI
opened later shows their waiting requests at once and does not evaluate the
repository again.

## Deploy secrets

```text
nix-secrets deploy [--repository PATH] [--backend-socket PATH] [--wait] HOST
```

The attached TUI must approve. Without `--wait`, success means the deployment
is queued. With `--wait`, the command waits and exits with an error if the
operator rejects the deployment or it fails. Missing values are skipped and
reported. `--allow-partial` is accepted for compatibility and has no effect.

## Group requests into a procedure

```text
nix-secrets procedure [--repository PATH] [--backend-socket PATH] --title TEXT [--steps N] -- COMMAND [ARGUMENT ...]
```

Runs COMMAND as one procedure. Every `nix-secrets` request that COMMAND or its
descendants make becomes a numbered step of one TUI dialog titled TEXT. This
covers `with-ssh-agent`, `with-secrets`, `pipe-secret`, `sign-artifacts`,
`sign-closure` and `deploy`. `--steps` declares how many steps the title shows,
as in `step 2/4`. The token in `NIX_SECRETS_PROCEDURE` admits only descendants
of this command. The procedure ends when COMMAND exits, and the command returns
COMMAND's exit status. If no backend is reachable, COMMAND still runs, and its
prompts appear one by one.

## Request plaintext for a command

These commands, including `--local`, cannot export operator keys declared
`signingOnly = true`, and the TUI cannot copy them.

```text
nix-secrets with-secrets [OPTIONS] IDENTIFIER... -- COMMAND [ARGUMENT ...]
nix-secrets pipe-secret [OPTIONS] IDENTIFIER -- COMMAND [ARGUMENT ...]
nix-secrets pipe-secret [OPTIONS] IDENTIFIER
```

The TUI shows the requested values and the requesting process. It displays
`--reason TEXT` as the caller's explanation without validating it.
Ctrl+Shift+Y or Yes approves. Enter, Esc or `n` denies. A request expires after
120 seconds unless the operator cancels the countdown with `c`. The command
then prints "operator cancelled the auto-reject countdown; waiting" and keeps
waiting. Inside a procedure, only the first step counts down. Without an
attached TUI, these commands print "no nix-secrets TUI is attached yet; waiting
until the operator opens it" and wait. Nothing is decrypted locally, and
nothing counts down until the TUI shows the request.

`with-secrets` asks once for the whole batch. It then runs the command with
`NIX_SECRETS_SESSION` pointing to a temporary private socket. Descendant
processes can use `pipe-secret` for those identifiers without another prompt.
The session refuses values outside the batch. The session ends when the command
exits, and `with-secrets` returns the command's exit status.

`pipe-secret -- COMMAND` sends the value to that command's stdin. Without a
command, it writes the value and no other output to stdout, and stdout must not
be a terminal. Outside an approved session, it requests approval for that one
value.

```sh
nix-secrets with-secrets HOST.services.signing.private-key \
  --reason 'Sign this release.' -- release-script
# Inside release-script:
nix-secrets pipe-secret HOST.services.signing.private-key -- signer --key-stdin
```

Approving a request gives the backend command the plaintext. Processes running
as the same user on that machine can read its memory, and the session socket
does not protect against them. See [Threat model](THREAT-MODEL.md#secret-requests-from-the-backend-host).

### Local decryption

`--local` decrypts in the calling process and does not ask the TUI. Use
`--secret-identity PATH` for a private identity file available at runtime, or
use the 1Password provider. By default the provider opens a separate 1Password
session. `--1password-shared-session` reuses the terminal's existing 1Password
authorization. `--schema-file PATH`, together with `--backend-socket`, applies
to local mode.

## Authenticate SSH from a backend command

```sh
nix-secrets with-ssh-agent --public-key ./login.pub \
  --destination operator@host.example \
  --reason 'Run the maintenance command.' -- \
  ssh -o IdentityAgent=SSH_AUTH_SOCK -o IdentitiesOnly=yes -i ./login.pub \
  -o StrictHostKeyChecking=yes operator@host.example maintenance-command
```

The temporary agent offers only the selected Ed25519 key. The client TUI asks
the operator to approve the SSH authentication challenge, then asks its local
agent to sign it. The backend receives only the signature. The private key
stays on the client.

The agent accepts only login challenges for that key and username. It refuses
requests that modify the agent, extension requests and Git signatures. Nothing
validates the hostname and reason the caller supplies, so SSH must verify the
host key. This relay is separate from the Git-only relay that the TUI commit
dialog uses.

## Sign boot artifacts on the client

```text
nix-secrets sign-artifacts --host HOST --reason TEXT IDENTIFIER < manifest.json
```

The attached TUI streams and hashes the immutable Nix store artifacts before it
shows the approval dialog. After approval, it decrypts the signing-only key once
on the client and returns detached signatures. The backend receives no private
key. The frontend requires a locally selected immutable `nmbl-sign` executable
in `NIX_SECRETS_ARTIFACT_SIGNER`. The sirati fleet's `nix-secrets-operator`
package sets this variable to its locked signer. Requests cannot select another
executable.

The input is a JSON object of bounded size with an `artifacts` field. Each entry
names its `role`, `path`, lowercase `sha512`, and `size`. The required roles are
`generation-image`, `boot-config`, `gen-kernel`, `gen-initrd`, and `rescue-sfs`.
`network-stage` and `rescue-tools` are optional. The output contains `signatures`, each with the
same role, digest and size, plus `signature_base64`. The caller must reject
missing or changed bindings.

### `sign-closure`

`nix-secrets sign-closure --host HOST --reason TEXT IDENTIFIER` reads version 1
Nix closure metadata from stdin and requests approval in the attached client TUI.
The client decrypts the signing-only operator key locally and writes standard
Nix Ed25519 signatures to stdout. The private key never reaches the backend.
The approval dialog labels the metadata as supplied by the requester. It does
not verify NAR contents. This command has no local decryption mode and no
private-key export mode.
