{
  lib,
  rustPlatform,
  git,
  age,
  openssh,
}:

rustPlatform.buildRustPackage {
  pname = "nix-secrets";
  version = "0.1.0";
  src = ../..;
  cargoLock.lockFile = ../../Cargo.lock;
  strictDeps = true;
  # The store tests compare records with a real git HEAD; deploy-time
  # generation tests encrypt with real age to a freshly generated SSH key.
  nativeCheckInputs = [
    git
    age
    openssh
  ];

  cargoBuildFlags = [
    "-p" "nix-secrets-backend"
    "-p" "nix-secrets-manager"
    "-p" "nix-secrets-deploy"
    "-p" "nix-secrets-transport"
    "-p" "secrets-ready-waiter"
  ];

  cargoTestFlags = [ "--workspace" ];

  meta = {
    description = "Repository-aware secret management and NixOS deployment";
    license = [ lib.licenses.mit lib.licenses.cc-by-40 ];
    mainProgram = "nix-secrets";
  };
}
