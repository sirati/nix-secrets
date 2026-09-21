{
  lib,
  rustPlatform,
  age,
  openssh,
}:

rustPlatform.buildRustPackage {
  pname = "nix-secrets-real-age-check";
  version = "0.1.0";
  src = ../..;
  cargoLock.lockFile = ../../Cargo.lock;
  strictDeps = true;
  nativeCheckInputs = [ age openssh ];
  cargoBuildFlags = [ "-p" "nix-secrets-crypto" ];
  cargoTestFlags = [
    "-p" "nix-secrets-crypto"
    "--features" "real-age-tests"
    "--test" "real_age_identity"
  ];
  installPhase = ''
    mkdir -p "$out"
    touch "$out/passed"
  '';
  meta = {
    description = "Real age SSH identity integration check for nix-secrets";
    license = lib.licenses.mit;
  };
}
