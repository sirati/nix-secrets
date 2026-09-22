# Implementation status

The repository implements the local editing and target deployment path in
[PROTOCOL.md](PROTOCOL.md).

## Implemented

- Fresh local or remote schema evaluation and safe same-user backend startup.
- Multiple frontends, atomic ciphertext-store updates, and claimed deployment
  approvals with rejection, cancellation, lease renewal, and retry behavior.
- A TUI tree with set/unset state, masked input, explicit paste, replacement
  confirmation, deployment requests, and provider retry.
- Direct age encryption to SSH recipients, with optional 1Password decryption
  and a runtime identity-file provider for automation.
- Frontend-owned OpenSSH, host-key classification and pinning, and a fixed
  no-shell byte relay.
- An authoritative target-manifest handshake followed by local decryption and
  bounded plaintext transfer inside SSH.
- Crash-atomic persistent generations, safe partial updates, strict ownership
  and modes, and bounded rollback history.
- Metadata-only service waiters and consumer-only systemd dependencies. SSH
  and `multi-user.target` remain independent; essential waiters participate in
  the configured boot-success check.
- Schema-authorized password, EFF passphrase, and encoded random-byte
  generation in the TUI, with masked preview, explicit reveal/copy, and
  replacement confirmation.
- NixOS modules, packages, apps, Rust tests, a real-age check, and NixOS VM
  tests for the service and deployment boundaries.

## Validation environment

The complete flake check passes. It runs the Rust workspace tests in release
mode, a real `age` encryption and decryption check, module evaluation checks,
and two NixOS VM tests. The VMs exercise the restricted SSH relay, atomic
deployment, rejection of malformed transactions, service ownership isolation,
consumer-only readiness dependencies, boot-health gating, and persistence over
a reboot.
