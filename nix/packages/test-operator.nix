# TEST-ONLY: nix-secrets with the headless `nix-secrets-test-operator`, for
# VM tests that deploy through the real operator path. Not exposed as a
# package; the flake's checks build it.
{ nix-secrets }:

nix-secrets.overrideAttrs (old: {
  pname = "nix-secrets-test-operator";
  cargoBuildFlags = old.cargoBuildFlags ++ [ "--features" "nix-secrets-manager/test-operator" ];
  # The workspace tests already ran in the package itself.
  doCheck = false;
})
