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
The one exception is values the operator explicitly sends to a program on the
backend host through a secret request, described below.

Nix evaluation is trusted to describe the intended hosts, services, secret
paths, recipients, and permissions. It receives no secret plaintext, so the Nix
store can be world-readable without disclosing a secret.

The target receiver installs each secret at its declared path with the
configured owner, group, and mode. Root on that target can read installed
secrets.

## Security properties

### Repository disclosure

A copy of Git history, `nix-secrets.toml`, or the Nix store reveals only
ciphertext and public metadata. Age encrypts and authenticates each complete
secret to the configured ordinary SSH recipients. SSH recipient encryption is
classical. Any claim about timing or side-channel resistance is limited to
what age, its dependencies, the 1Password provider, and the operating system
provide.

### Backend compromise

A compromised backend can delete, withhold, replay, or reorder stored
ciphertexts, and it can deny service. It cannot decrypt values without a
recipient private key. Age detects modification of its ciphertext. Age does
not authenticate the outer TOML metadata, so the encrypted inner payload
repeats the canonical identifier and opaque version. Decryption requires the
requested identifier, the map key, the outer metadata, and the authenticated
inner values to agree. This rejects substitution of one identifier's record for
another and tampering with the outer version. An attacker can still replay an
older complete record for the same identifier, unless repository history or a
separately trusted monotonic revision detects it.

The backend may serve several frontend processes. It accepts each Unix-socket
connection only after it reads the kernel peer credentials and confirms that
the peer's effective UID equals the backend UID. Socket permissions alone do
not authenticate the peer.

A compromised process running as the same Unix user is outside this local
isolation boundary. Where that risk must be isolated, use separate Unix
accounts.

### Relay compromise

The backend, the deployer, and the forwarding socket carry the target SSH
stream without terminating it. The TUI authenticates the final target with its
local OpenSSH configuration and `known_hosts`. A relay can observe timing and
byte counts or deny service. To read or alter accepted deployment plaintext it
would have to break SSH authentication or transport integrity.

Changed host keys fail closed. The UI never accepts an unknown host silently.
It shows the presented key and any existing known-host aliases with that key.

### SSH keys

SSH keys have two explicit roles. OpenSSH uses host and user keys to
authenticate the remote backend and the final target. Age encrypts stored
secrets to configured SSH public keys. Each role uses its established
protocol-specific implementation, and the code must not convert keys between
the roles ad hoc.

Recipient decryption uses `age-plugin-1p`, which asks the 1Password CLI for the
matching SSH private key in memory. No private key file is required. This is
not an SSH-agent operation. The agent stays available to authenticate SSH
connections, and 1Password policy controls access to stored key material.
An unlocked 1Password session may not prompt for every request, so the UI must
not claim that every decryption caused a new approval prompt.

### Target compromise

Root compromise of a target exposes all secrets currently installed there.
Unattended reboot requires persistent storage, so a reboot does not end that
exposure. The receiver accepts only the target's declared leaves and applies
their configured filesystem ownership and permissions.

A target cannot request arbitrary repository values. The TUI and the target
both validate its request against the declaration each evaluated on its own,
and the user approves the displayed set before decryption.

### Generated Storage Box credentials

The encrypted Storage Box password is a bootstrap task input. The frontend and
the target see it only during an approved task, and the target never publishes
it into its persistent secret generation. The target-generated Ed25519 private
key never leaves the target, and the target installs it only at the declared
output path.

The frontend contributes fresh operating-system randomness to each approved
attempt. The target writes it to `/dev/urandom` before it draws its own OS
randomness. Linux mixes writes into the random pool without crediting entropy.
The contribution is therefore an extra layer of defense, and the design does
not trust it. Target key security still depends on the target OS CSPRNG. The
frontend contribution and the target seed are zeroized after use.

Storage Box host keys are complete pinned public keys from the Nix manifest.
Changed or unlisted keys fail closed. The authorized-keys update replaces one
stable task marker and rejects duplicate or malformed marker entries. Crash
recovery can therefore leave at most one active task key, and unrelated entries
stay in place. A malicious Storage Box can reject access or discard updates. It
learns the generated public key and receives the password authentication, but
it never receives the generated private key.

### Frontend compromise

A compromised TUI process can capture entered, pasted, decrypted, or approved
secrets and can authorize deployment. The design cannot protect plaintext from
the process that must display or transmit it. Clipboard use also inherits the
security properties of the user's desktop clipboard.

A 1Password rejection or unlock failure does not cause a fallback to weaker
encryption or a partial deployment.

### Secret requests from the backend host

`with-secrets` and `pipe-secret` let a program on the backend host obtain
values. Decryption stays in the TUI. Plaintext reaches the backend host only
when the operator approves in the TUI's modal. The modal shows every value, its
recipient keys, and the requester's PID, executable, command line, and working
directory. The backend reads these from `/proc` for the peer PID the kernel
reports, so a requester cannot misreport itself. At most 16 requests wait at
once. A prompt never takes the screen from a dialog that is already open. A
prompt that arrives meanwhile waits minimised in the task bar until the
operator restores it. A key meant for one dialog therefore cannot answer
another dialog that appeared under it. Approval needs the same deliberate key
as the loss warning. A request outside a procedure, or the first step of one,
denies itself after 120 seconds unless the operator cancels that countdown.

The command that registered a procedure chooses its title. The TUI shows the
title without validating it, as it shows a reason. The backend admits a request
to a procedure only with the procedure's random token. It also requires that
the requester descends from the registering process. Another program of the
same user therefore cannot place its prompt in a procedure's dialog under that
title unless it runs inside the procedure. The prompt body still names the
actual requester as the backend read it from `/proc`.

Approved values then stay in backend memory for the lifetime of the command.
The backend serves them on a 0600 socket in a 0700 directory, only to same-UID
processes that descend from the requester, and only for the approved
identifiers. It refuses a value outside the batch and does not prompt again.
The socket and values are removed when the command exits or the requester
disconnects.

Other processes of the same user on the backend host can still reach the
values, because such a process can read the requester's memory or ptrace it.
The descendant check only prevents accidental use by unrelated programs.
Approve only requests whose program, command, and directory you expect, on a
backend host whose user account you trust with the values.

## Availability and recovery

The receiver detects incomplete deployments and keeps a bounded history of
previous secret generations for local rollback. If the ciphertext store is
deleted, the operator must restore it from a copy they made.

The receiver stages and validates an entire requested generation on the
persistent filesystem before one crash-atomic `.current` pointer switch.
It copies unrequested secrets into distinct inodes, so rollback generations
stay intact even when a consumer can modify its current file. A consuming unit
waits for its declared secrets. `multi-user.target` does not depend on a global
secret-ready service. SSH starts independently, so repair and initial
deployment stay possible.

## Standards and implementation references

- [The age manual](https://github.com/FiloSottile/age/blob/main/doc/age.1.html)
  documents SSH recipients and the private-key identity requirements.
- [RFC 9987](https://www.rfc-editor.org/info/rfc9987/) specifies the OpenSSH
  agent protocol around signing requests. The protocol has no general KEM
  decapsulation operation for age SSH recipients.
