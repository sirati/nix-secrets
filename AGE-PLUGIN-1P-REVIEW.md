# `age-plugin-1p` integration review

## Decision

The 1Password provider is an opt-in package, `nix-secrets-1password`. The
default package does not download or expose `age`, `age-plugin-1p`, or `op`.
The provider gives age access to the matching SSH identity when decrypting a
complete age ciphertext. There is no project-defined content cipher or key.

Encryption uses an ordinary `ssh-ed25519` or `ssh-rsa` public recipient and
does not need 1Password. Decryption runs `age --decrypt -j 1p`; age invokes
`age-plugin-1p`, which retrieves the matching SSH private key through the
1Password CLI. This is 1Password CLI authorization, not an SSH-agent signing
operation. Whether every request displays an approval prompt depends on the
1Password application policy and current session state.

## Pinned supply chain

The flake pins nixpkgs revision
`e554fab72f81915600f3f449b786fd9af40439a5`. Its package definition pins:

- `age-plugin-1p` version `0.1.0` / tag `v0.1.0`;
- source hash `sha256-QYHHD7wOgRxRVkUOjwMz5DV8oxlb9mmb2K4HPoISguU=`;
- vendored Go dependency hash
  `sha256-WrdwhlaqciVEB2L+Dh/LEeSE7I3+PsOTW4c+0yOKzKY=`;
- `age` version `1.3.1` through the same nixpkgs revision.

This avoids an additional flake input and keeps the provider dependencies lazy:
they are realized only when the opt-in package or app is selected.

## Reviewed behavior

The published `v0.1.0` API exposes functions that list SSH fingerprints through
`op`, locate keys by SSH public key, and read a private key through `op`. Its
default identity implements age stanza unwrapping. Upstream documents that:

- encryption uses normal age SSH recipients and needs neither the plugin nor
  1Password;
- `age --decrypt -j 1p` selects the data-less `1p` identity;
- only Ed25519 and RSA SSH keys are supported.

The project process starts `age` with fixed arguments. Plaintext and ciphertext
travel through anonymous stdin/stdout pipes. They are never put in argv, an
environment variable, or a file. Rust-side plaintext buffers are zeroized
after use. SSH public recipients are public and may appear in argv.

## Trust statement

The flake uses the `age-plugin-1p` package from its pinned nixpkgs revision.
That revision and nixpkgs' fixed source and vendor hashes make the selected
source immutable and reproducible; they are not proof that the implementation
is correct. The local review confirmed the published API and invocation
boundary but could not inspect every Go source line because the source was not
realized and network fetching was unavailable. This is recorded as review
scope rather than a deployment blocker. If nixpkgs stops packaging the plugin,
this flake must pin its source and dependency/vendor hash directly.

## References

- [`age-plugin-1p` repository and usage](https://github.com/Enzime/age-plugin-1p)
- [`age-plugin-1p` v0.1.0 published API](https://pkg.go.dev/github.com/Enzime/age-plugin-1p@v0.1.0/plugin)
- [age SSH-recipient and plugin behavior](https://github.com/FiloSottile/age/blob/main/doc/age.1.html)
- [OpenSSH agent protocol, RFC 9987](https://www.rfc-editor.org/info/rfc9987/)
