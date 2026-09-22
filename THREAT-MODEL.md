# Threat model

## Assets

The system protects:

- secret plaintext and recipient private keys;
- the integrity of the declared secret tree;
- the identity of the final deployment target;
- installed file ownership and permissions;
- the atomicity of a deployed secret generation.

The secret names, tree shape, recipients, target names, and ciphertext sizes
are metadata. They are not confidential.

## Trust boundaries

The local TUI is the only component that decrypts stored values. During an
approved deployment, the final target also receives the values it requires.
The repository backend and deployment relays are not trusted with plaintext.

Nix evaluation is trusted to describe the intended hosts, services, secret
paths, recipients, and permissions. It receives no secret plaintext. The Nix
store can therefore be world-readable without disclosing a secret.

The target receiver installs each secret at its declared path with the
configured owner, group, and mode. Root on that target can read installed
secrets.

## Security properties

### Repository disclosure

Copying Git history, `nix-secrets.toml`, or the Nix store reveals ciphertext
and public metadata only. Age encrypts and authenticates each complete secret
to the configured ordinary SSH recipients. SSH recipient encryption is
classical. Claims about timing or side-channel resistance are limited to age,
its dependencies, the 1Password provider, and the operating system.

### Backend compromise

A compromised backend can delete, withhold, replay, or reorder stored
ciphertexts and can deny service. It cannot decrypt values without a recipient
private key. Age detects modification of its ciphertext. Age does not
directly authenticate the outer TOML metadata, so the encrypted inner payload
duplicates the canonical identifier and opaque version. Decryption requires
the requested identifier, map key, outer metadata, and authenticated inner
values to agree. This rejects cross-identifier substitution and outer-version
tampering. Replaying an older complete record for the same identifier remains
possible unless repository history or a separately trusted monotonic revision
detects it.

The backend may serve several frontend processes. Each Unix-socket connection
is accepted only after checking kernel peer credentials and confirming the
peer effective UID equals the backend UID. Socket permissions alone are not
the authentication check.

Compromise of another process running as the same Unix user is outside this
local isolation boundary. Separate Unix accounts are required where that risk
must be isolated.

### Relay compromise

The backend, deployer, and forwarding socket transport the target SSH stream
without terminating it. The TUI authenticates the final target using its local
OpenSSH configuration and `known_hosts`. A relay can observe timing and byte
counts or deny service, but cannot read or alter accepted deployment plaintext
without breaking SSH authentication or transport integrity.

Changed host keys fail closed. An unknown host is never silently accepted; the
UI shows the presented key and any existing known-host aliases with that key.

### SSH keys

SSH keys have two explicit roles. OpenSSH uses host and user keys to
authenticate the remote backend and final target. Separately, age encrypts
stored secrets to configured SSH public keys.
These roles use established protocol-specific implementations and must not be
mixed by ad-hoc conversion.

Recipient decryption uses `age-plugin-1p`, which asks the 1Password CLI for the
matching SSH private key in memory. No private key file is required. This is
not an SSH-agent operation: the agent remains available for authenticating SSH
connections, while 1Password policy controls access to stored key material.
An unlocked 1Password session may not prompt for every request, so the UI must
not claim that every decryption necessarily caused a new approval prompt.

### Target compromise

Root compromise of a target exposes all secrets currently installed there.
Persistent storage is required for unattended reboot, so reboot does not erase
that exposure. The receiver accepts only the target's declared leaves and
applies their configured filesystem ownership and permissions.

A target cannot request arbitrary repository values. Both the TUI and target
validate its request against the independently evaluated declaration, and the
user approves the displayed set before decryption.

### Generated Storage Box credentials

The encrypted Storage Box password is a bootstrap task input. The frontend and
target see it only during an approved task, and it is never published into the
target's persistent secret generation. The target-generated Ed25519 private
key never leaves the target and is installed only at the declared output path.

The frontend contributes fresh operating-system randomness to each approved
attempt. The target writes it to `/dev/urandom` before drawing its own OS
randomness. Linux mixes writes into the random pool without crediting entropy;
the contribution is therefore defense in depth and is not trusted. Target key
security still depends on the target OS CSPRNG. The frontend contribution and
target seed are zeroized after use.

Storage Box host keys are complete pinned public keys from the Nix manifest.
Changed or unlisted keys fail closed. The authorized-keys update replaces one
stable task marker and rejects duplicate or malformed marker entries, limiting
crash recovery to one active task key while preserving unrelated entries.
A malicious Storage Box can reject access or discard updates. It learns the
generated public key and necessarily receives the password authentication, but
it never receives the generated private key.

### Frontend compromise

A compromised TUI process can capture entered, pasted, decrypted, or approved
secrets and can authorize deployment. The design cannot protect plaintext from
the process that must display or transmit it. Clipboard use also inherits the
security properties of the user's desktop clipboard.

1Password rejection and unlock failures do not cause fallback to weaker
encryption or partial deployment.

## Availability and recovery

The receiver detects incomplete deployments and retains a bounded history of
previous secret generations for local rollback. A deleted ciphertext store
requires restoration from a copy made by the operator.

The receiver stages and validates an entire requested generation on the
persistent filesystem before one crash-atomic `.current` pointer switch.
Unrequested secrets are copied into distinct inodes, preserving rollback
generations even when a consumer can modify its current file. A consuming unit
waits for its declared secrets; `multi-user.target` does not depend on a global
secret-ready service. SSH starts independently to permit repair and initial
deployment.

## Standards and implementation references

- [The age manual](https://github.com/FiloSottile/age/blob/main/doc/age.1.html)
  documents SSH recipients and the private-key identity requirements.
- [RFC 9987](https://www.rfc-editor.org/info/rfc9987/) specifies the OpenSSH
  agent protocol around signing requests; it does not expose general KEM
  decapsulation for age SSH recipients.
