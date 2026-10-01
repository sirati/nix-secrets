# 1Password integration

Install `nix-secrets-1password` on the operator machine and enable the
1Password desktop app's CLI integration. On NixOS, `programs._1password`
provides the required setgid `/run/wrappers/bin/op`; the bundled CLI does not
replace that wrapper.

Encryption needs only an ordinary `ssh-ed25519` or `ssh-rsa` public key.
Decryption needs the matching private key from 1Password. SSH-agent signing
cannot decrypt an age SSH-recipient ciphertext.

## What decryption authorizes

The provider validates a batch of ciphertexts, lists SSH-key fingerprints,
selects one key shared by the batch, then reads only that private key through
`op read`. It passes the key to age on an inherited pipe. Keys and plaintext
are not passed in arguments, environment variables or temporary files; the
provider zeroizes its secret buffers after use.

1Password desktop CLI approval is scoped to an account and session, not to an
individual vault or item. Authorizing nix-secrets therefore grants broader CLI
access than the single key the provider chooses to read. By default the
provider starts a separate session for the operation.
`--1password-shared-session` instead reuses the terminal's authorization;
see [Command reference](COMMANDS.md#local-decryption). An existing authorization
may mean no new prompt appears.

The TUI uses its one-key launcher, not `age -j 1p`, whose default plugin path
reads every SSH private key in the account. The package still bundles
`age-plugin-1p` for direct use outside the TUI. Dependency revisions are pinned
by [flake.lock](flake.lock) and the selected nixpkgs package definitions.

## References

- [1Password CLI app-integration security](https://developer.1password.com/docs/cli/app-integration-security/)
- [1Password secret references](https://developer.1password.com/docs/cli/secret-reference-syntax/)
- [age SSH recipients](https://github.com/FiloSottile/age/blob/main/doc/age.1.html)
- [`age-plugin-1p`](https://github.com/Enzime/age-plugin-1p)
- [Threat model](THREAT-MODEL.md)
