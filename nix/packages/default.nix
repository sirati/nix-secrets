{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "nix-secrets";
  version = "0.1.0";
  src = ../..;
  cargoLock.lockFile = ../../Cargo.lock;
  strictDeps = true;

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
