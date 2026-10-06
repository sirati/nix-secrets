# Threat model

## Trust boundaries

Only the TUI decrypts stored values. A target receives plaintext for the leaves
deployed to it. The backend and the relays see only ciphertext, except for
values the operator releases through a [secret request](#secret-requests).

Nix evaluation is trusted to describe the hosts, paths, recipients and
permissions correctly. It never sees plaintext, so the Nix store may be world
readable. Secret names, tree shape, recipients, targets and ciphertext sizes
are public.

## Repository and backend

Git history, `nix-secrets.toml` and the Nix store contain only ciphertext and
public metadata. Age encrypts each value to classical SSH recipients.

A compromised backend can delete, withhold or replay records and deny service.
It cannot decrypt. The encrypted payload repeats the identifier and version,
so a record cannot be moved to another identifier. An older record for the
same identifier can be replayed.

The backend accepts only peers with its own effective UID. Any process of that
user is inside the trust boundary. Use separate accounts to isolate it.

## Deployment

The relays carry the target's SSH stream without terminating it. The TUI
authenticates the target with the user's OpenSSH configuration and
`known_hosts`, so a relay can only observe sizes and timing or deny service. A
changed host key aborts, and an unknown key needs explicit trust.

A target cannot request arbitrary values. The TUI and the target each check
the selection against their own evaluation, and the operator approves the list
before decryption. Root on a target can read everything installed there,
across reboots.

## Operator machine

A compromised TUI can read every value it decrypts or receives and can approve
deployments. Copied values are exposed to the desktop clipboard. 1Password
keys and plaintext never appear in arguments, environment variables or files.
An unlocked 1Password session may not prompt for each decryption.

## Secret requests

`with-secrets` and `pipe-secret` release plaintext to a program on the backend
host. The prompt shows the requester's PID, executable, arguments and working
directory, which the backend reads from `/proc` for the PID the kernel reports.
The `--reason` text and procedure titles come from the requester and are not
validated.

Approved values stay in backend memory until the command exits. Any process of
the same user can read them through ptrace or `/proc`. The check that a session
client descends from the requester prevents accidental use only.

## Storage Box keys

The password reaches only the TUI and the target. The generated private key
never leaves the target. The TUI's random contribution is mixed in without
entropy credit, so the key's strength rests on the target's kernel RNG. A
malicious Storage Box can refuse service and learns the password and the public
key.

## Availability

The receiver switches a complete generation atomically and keeps the last
three. Consumers wait for their own secrets. `multi-user.target` and SSH do
not, so a host without secrets still boots and accepts deployments.
