# `age-plugin-1p` integration review

## Decision

The 1Password provider is an opt-in package, `nix-secrets-1password`. The
default package does not download or expose `age`, `age-plugin-1p`, or `op`.
There is no project-defined content cipher or key.

Encryption uses an ordinary `ssh-ed25519` or `ssh-rsa` public recipient and
does not need 1Password.

Decryption no longer uses `age -j 1p`. The TUI runs every 1Password
decryption, for one value or a whole deployment, through
`nix-secrets-1password --batch --one-key age --decrypt`. That launcher:

1. reads all ciphertexts first, so a malformed input never prompts;
2. runs `op item list --categories "SSH Key" --format=json`, which returns
   item metadata only: IDs, titles, vaults, and each key's SHA-256
   fingerprint. It holds no key material, and this first `op` call raises
   the one authorization prompt;
3. picks the one item whose fingerprint matches an `ssh-ed25519`/`ssh-rsa`
   stanza tag of every ciphertext. age tags a stanza with the first four
   bytes of SHA-256 over the key blob, the same hash as the fingerprint.
   Nothing is decrypted to find it;
4. reads only that key with `op read "op://<vault-id>/<item-id>/private key"`;
5. passes it to each `age --decrypt --identity /dev/fd/3` run on an
   inherited pipe. The key is never put in argv, the environment or a file,
   and it is zeroized when the launcher exits.

The earlier `age -j 1p` path ran `op item list | op item get - --fields
private_key` (age-plugin-1p `plugin/op.go`, `ReadAllKeysOp`) and so read the
private key of every SSH Key item in the account for each decryption.

## What the 1Password prompt grants

This cannot be narrowed further with the desktop-app integration. 1Password
authorizes the CLI per account, for the requesting terminal session (or
session leader), for 10 minutes of use and at most 12 hours
(<https://developer.1password.com/docs/cli/app-integration-security/>). The
prompt names the account and the requesting process, never a vault or an
item, and `op read` raises the same prompt as `op item list`. Vault-scoped
access exists only for service accounts and Connect servers. Both need a
bearer token and have no biometric path, and a service account cannot reach
Personal/Private vaults.

What changed is what the authorized session is used for:
- it reads exactly one private key;
- it runs in its own session, so the grant ends with the launcher (see
  README "Encryption");
- it costs one prompt per deployment or secret request.

With `--1password-shared-session`, the launcher keeps the caller's session,
and the grant stays usable from that terminal for its 10 minutes.

An SSH agent cannot replace the export: decrypting an `ssh-ed25519` age
stanza needs the X25519 scalar derived from the key's seed (age
`agessh.go`), and the agent protocol offers only signatures.

## Pinned supply chain

The flake pins nixpkgs revision
`e554fab72f81915600f3f449b786fd9af40439a5`. Its package definition pins:

- `age-plugin-1p` version `0.1.0` / tag `v0.1.0`;
- source hash `sha256-QYHHD7wOgRxRVkUOjwMz5DV8oxlb9mmb2K4HPoISguU=`;
- vendored Go dependency hash
  `sha256-WrdwhlaqciVEB2L+Dh/LEeSE7I3+PsOTW4c+0yOKzKY=`;
- `age` version `1.3.1` through the same nixpkgs revision.

The plugin is still bundled for single decryptions outside the launcher.
The TUI never uses it.

## Reviewed behavior

The plugin source at the pinned revision was read. `plugin/op.go` has
`ReadAllKeysOp` (the `-j 1p` default identity) and `ReadKeyFromPubKeyOp`,
which lists fingerprints and then `op read`s one key. The launcher uses the
second approach itself, without the plugin in the trust path.

The project process starts `age` with fixed arguments. Plaintext and ciphertext
travel through anonymous stdin/stdout pipes. They are never put in argv, an
environment variable, or a file. Rust-side plaintext buffers are zeroized
after use. SSH public recipients are public and may appear in argv.

## References

- [`age-plugin-1p` repository and usage](https://github.com/Enzime/age-plugin-1p)
- [1Password CLI app integration security](https://developer.1password.com/docs/cli/app-integration-security/)
- [1Password secret reference syntax](https://developer.1password.com/docs/cli/secret-reference-syntax/)
- [age SSH-recipient and plugin behavior](https://github.com/FiloSottile/age/blob/main/doc/age.1.html)
