# Commands

These commands run on the machine with the repository. They accept
`--repository PATH`, which defaults to the working directory, and
`--backend-socket PATH`. Without `--backend-socket` they start the repository's
backend if none is running.

Each request waits until a TUI is attached and the operator answers it. A
request for values or signatures is denied 120 seconds after the TUI shows it,
unless the operator cancels that countdown. Inside a procedure only the first
step has a countdown. Deployment requests have none.

## deploy

```text
nix-secrets deploy [--wait] HOST
```

Queues a deployment of every deployable leaf of HOST. Without `--wait`, it
exits once the request is queued. With `--wait`, it exits non-zero if the
operator rejects the deployment or it fails. `--allow-partial` is accepted and
has no effect, because missing values are always skipped and listed.

## procedure

```text
nix-secrets procedure --title TEXT [--steps N] -- COMMAND [ARGUMENT ...]
```

Runs COMMAND. Every request that COMMAND or its descendants make becomes a
numbered step of one approval dialog titled TEXT. `--steps` sets the total
shown in `step 2/4`. COMMAND receives the token in `NIX_SECRETS_PROCEDURE`.
The command exits with COMMAND's status. If no backend is reachable, COMMAND
still runs and its requests appear one by one.

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

## with-ssh-agent

```sh
nix-secrets with-ssh-agent --public-key ./login.pub \
  --destination operator@host.example --reason 'Run maintenance.' -- \
  ssh -o IdentityAgent=SSH_AUTH_SOCK -o IdentitiesOnly=yes -i ./login.pub \
  -o StrictHostKeyChecking=yes operator@host.example maintenance-command
```

Runs COMMAND with a temporary agent that offers only the given Ed25519 key.
Each signature request goes to the TUI, and the operator's own agent signs it.
The agent signs only SSH user authentication for that key and user. Nothing
checks the host name, so the SSH client must verify the host key.

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
