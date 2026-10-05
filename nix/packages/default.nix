{
  lib,
  rustPlatform,
  git,
  age,
  openssh,
  util-linux,
  perl,
  acl,
  runCommand,
}:

let
  # Public test trust only: no private key is generated or stored here.
  managedKnownHosts = runCommand "nix-secrets-managed-known-hosts-fixture" { } ''
    mkdir -p "$out/etc/ssh" "$out/store-generation/ssh"
    printf '%s\n' '[ns1.example]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f' > "$out/store-generation/ssh/ssh_known_hosts"
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
  passthru.deploymentProtocolVersion = 4;

  meta = {
    description = "Repository-aware secret management and NixOS deployment";
    license = [ lib.licenses.mit lib.licenses.cc-by-40 ];
    mainProgram = "nix-secrets";
  };
}
