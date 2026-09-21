{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "secrets-ready-waiter";
  version = "0.1.0";
  src = ../..;
  cargoLock.lockFile = ../../Cargo.lock;
  cargoBuildFlags = [ "-p" "secrets-ready-waiter" ];
  cargoTestFlags = [ "-p" "secrets-ready-waiter" ];
  strictDeps = true;

  meta = {
    description = "Wait until declared persistent secret files exist";
    license = lib.licenses.mit;
    mainProgram = "secrets-ready-waiter";
  };
}
