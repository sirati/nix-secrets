# Command reference

## Repository and backend

```text
nix-secrets [SSH_ARG ...] -- REPOSITORY
```

With no SSH arguments the repository is local. Otherwise OpenSSH receives the
arguments individually, and the backend expands a leading `~/` remotely.
Repository configuration chooses the backend socket; discovery checks same-user
peer credentials. Multiple frontends can share a backend.

Commands below run on the repository/backend machine. They accept
`--repository PATH` (default: working directory) and `--backend-socket PATH`.

## Deploy secrets

```text
nix-secrets deploy [--repository PATH] [--backend-socket PATH] [--wait] HOST
```

The attached TUI must approve. Without `--wait`, success means queued; with it,
the command waits and exits unsuccessfully on rejection or deployment failure.
Missing values are skipped and reported. `--allow-partial` is accepted for
compatibility and has no effect.

## Request plaintext for a command

```text
nix-secrets with-secrets [OPTIONS] IDENTIFIER... -- COMMAND [ARGUMENT ...]
nix-secrets pipe-secret [OPTIONS] IDENTIFIER -- COMMAND [ARGUMENT ...]
nix-secrets pipe-secret [OPTIONS] IDENTIFIER
```

The TUI shows the requested values and the requesting process. `--reason TEXT`
is displayed as an unvalidated caller explanation. Ctrl+Shift+Y or Yes approves;
Enter, Esc or `n` denies. Requests expire after 120 seconds. Without an attached
TUI, these commands fail rather than decrypting locally.

`with-secrets` asks once for the batch, then runs the command with
`NIX_SECRETS_SESSION` pointing to a temporary private socket. Descendants can
use `pipe-secret` for those identifiers without another prompt. Values outside
the batch are refused. The session ends with the command, and its exit status
is returned.

`pipe-secret -- COMMAND` sends the value to that command's stdin. Without a
command, it writes only the value to stdout; stdout must not be a terminal.
Outside an approved session it requests approval for that one value.

```sh
nix-secrets with-secrets HOST.services.signing.private-key \
  --reason 'Sign this release.' -- release-script
# Inside release-script:
nix-secrets pipe-secret HOST.services.signing.private-key -- signer --key-stdin
```

Approval trusts the backend command with plaintext. Same-user processes on
that machine can access its memory; the session socket is not a security
boundary against them. See [Threat model](THREAT-MODEL.md#secret-requests-from-the-backend-host).

### Local decryption

`--local` explicitly decrypts in the calling process instead of asking the TUI.
Use `--secret-identity PATH` for a runtime private identity file, or the
1Password provider. `--1password-shared-session` reuses the terminal's existing
1Password authorization; by default the provider uses a separate session.
`--schema-file PATH`, with `--backend-socket`, applies to the local mode.

## Authenticate SSH from a backend command

```sh
nix-secrets with-ssh-agent --public-key ./login.pub \
  --destination operator@host.example \
  --reason 'Run the maintenance command.' -- \
  ssh -o IdentityAgent=SSH_AUTH_SOCK -o IdentitiesOnly=yes -i ./login.pub \
  -o StrictHostKeyChecking=yes operator@host.example maintenance-command
```

The temporary agent exposes only the selected Ed25519 key. The client TUI
approves the SSH authentication challenge, then asks its local agent to sign.
Only the signature returns to the backend; the private key stays on the client.

Only login challenges for that key and username are allowed. Agent mutations,
extensions and Git signatures are refused. The caller's hostname and reason
are unvalidated claims: SSH must verify the host key. This relay is separate
from the Git-only relay used by the TUI commit dialog.
