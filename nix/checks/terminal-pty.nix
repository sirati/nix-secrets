{
  lib,
  stdenv,
  rustPlatform,
  age,
  openssh,
  python3,
}:

# The production TUI and backend in a real PTY, read by a terminal emulator
# (pyte) whose alternate screen keeps what was printed before it.
rustPlatform.buildRustPackage {
  pname = "nix-secrets-terminal-pty-check";
  version = "0.1.0";
  src = ../..;
  cargoLock.lockFile = ../../Cargo.lock;
  strictDeps = true;
  nativeCheckInputs = [
    age
    openssh
  ];
  cargoBuildFlags = [
    "-p" "nix-secrets-backend"
    "-p" "nix-secrets-manager"
    "--bin" "nix-secrets-backend"
    "--bin" "nix-secrets"
  ];
  cargoTestFlags = [
    "-p" "nix-secrets-manager"
    "--test" "closure_signing_pty"
  ];
  preCheck = ''
    export NIX_SECRETS_PYTE_PYTHON=${python3.withPackages (ps: [ ps.pyte ])}/bin/python3
    export NIX_SECRETS_TEST_BACKEND=$PWD/target/${stdenv.hostPlatform.rust.cargoShortTarget}/release/nix-secrets-backend
    export NIX_SECRETS_PTY_PROOF_DIRECTORY=$TMPDIR/pty-proof
    test -x "$NIX_SECRETS_TEST_BACKEND"
  '';
  installPhase = ''
    mkdir -p "$out"
    cp "$NIX_SECRETS_PTY_PROOF_DIRECTORY/approval-screen.txt" "$out/"
  '';
  meta = {
    description = "Production TUI closure approval through a real PTY";
    license = lib.licenses.mit;
  };
}
