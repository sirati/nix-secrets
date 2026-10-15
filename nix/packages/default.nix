{
  lib,
  rustPlatform,
  git,
  age,
  openssh,
  util-linux,
  perl,
  acl,
  dbus,
  runCommand,
}:

let
  # Public test trust only: no private key is generated or stored here.
  # Plain `cargo test` builds the same tree from the same file; see
  # managed_fixture() in crates/transport/src/hostkey/persist.rs.
  managedKnownHosts = runCommand "nix-secrets-managed-known-hosts-fixture" { } ''
    mkdir -p "$out/etc/ssh" "$out/store-generation/ssh"
    cp ${../../crates/transport/tests/fixtures/managed_ssh_known_hosts} "$out/store-generation/ssh/ssh_known_hosts"
    ln "$out/store-generation/ssh/ssh_known_hosts" "$out/store-generation/optimized-copy"
    ln -s ../store-generation "$out/etc/static"
    ln -s ../static/ssh/ssh_known_hosts "$out/etc/ssh/ssh_known_hosts"
    ln -s loop "$out/loop"
  '';
in
rustPlatform.buildRustPackage {
  pname = "nix-secrets";
  version = "0.1.0";
  src = ../..;
  cargoLock.lockFile = ../../Cargo.lock;
  strictDeps = true;
  NIX_SECRETS_MANAGED_KNOWN_HOSTS_FIXTURE = managedKnownHosts;
  NIX_SECRETS_SIGNING_TEST_ARTIFACT = "${../..}/README.md";
  # The store tests compare records with a real git HEAD; deploy-time
  # generation tests encrypt with real age to a freshly generated SSH key.
  nativeCheckInputs = [
    git
    age
    openssh
    # `script` gives the pipe-secret test a real terminal to refuse.
    util-linux
    # A stand-in for the 1Password launcher's batch framing in a unit test.
    perl
    # Readiness regressions inspect real POSIX ACL metadata.
    acl
    # Desktop notifications go through a private session bus in a test.
    dbus
  ];

  cargoBuildFlags = [
    "-p" "nix-secrets-backend"
    "-p" "nix-secrets-manager"
    "-p" "nix-secrets-deploy"
    "-p" "nix-secrets-transport"
    "-p" "secrets-ready-waiter"
  ];

  cargoTestFlags = [ "--workspace" ];

  # The deployment protocol its receiver speaks; see DEPLOYMENT_PROTOCOL_VERSION.
  passthru.deploymentProtocolVersion = 5;

  meta = {
    description = "Repository-aware secret management and NixOS deployment";
    license = [ lib.licenses.mit lib.licenses.cc-by-40 ];
    mainProgram = "nix-secrets";
  };
}
