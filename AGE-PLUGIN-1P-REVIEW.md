# 1Password integration

Install `nix-secrets-1password` on the operator machine and enable CLI
integration in the 1Password desktop app. On NixOS, `programs._1password`
provides the required setgid `/run/wrappers/bin/op`. The bundled CLI does not
replace that wrapper.

Encryption needs only an ordinary `ssh-ed25519` or `ssh-rsa` public key.
Decryption needs the matching private key from 1Password. Signing through the
SSH agent cannot decrypt a ciphertext encrypted to an age SSH recipient.

## What decryption authorizes

The provider validates a batch of ciphertexts, lists the SSH key fingerprints,
and selects one key that the whole batch shares. It then reads only that
private key through `op read` and passes it to age on an inherited pipe. Keys
and plaintext never appear in arguments, environment variables or temporary
files. The provider zeroizes its secret buffers after use.

The 1Password desktop app approves CLI access for an account and session. It
cannot limit the approval to one vault or item. Authorizing nix-secrets
therefore gives CLI access to more than the single key the provider reads. By
default the provider starts a separate session for the operation.
`--1password-shared-session` reuses the terminal's authorization instead.
See [Command reference](COMMANDS.md#local-decryption). If an authorization
already exists, no new prompt may appear.

The TUI uses its own launcher, which reads one key. It does not use
`age -j 1p`, because that plugin's default path reads every SSH private key in
the account. The package still bundles `age-plugin-1p` for direct use outside
the TUI. [flake.lock](flake.lock) and the selected nixpkgs package definitions
pin the dependency revisions.

## References

- [1Password CLI app-integration security](https://developer.1password.com/docs/cli/app-integration-security/)
- [1Password secret references](https://developer.1password.com/docs/cli/secret-reference-syntax/)
- [age SSH recipients](https://github.com/FiloSottile/age/blob/main/doc/age.1.html)
- [`age-plugin-1p`](https://github.com/Enzime/age-plugin-1p)
- [Threat model](THREAT-MODEL.md)
