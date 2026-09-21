{
  lib,
  pkgs,
  makeWrapper,
  symlinkJoin,
  nix-secrets,
}:

let
  ageWithOnePassword = pkgs.age.withPlugins (plugins: [ plugins.age-plugin-1p ]);
in
symlinkJoin {
  name = "nix-secrets-with-1password";
  paths = [ nix-secrets ];
  nativeBuildInputs = [ makeWrapper ];
  postBuild = ''
    wrapProgram "$out/bin/nix-secrets" \
      --prefix PATH : ${lib.makeBinPath [ ageWithOnePassword pkgs._1password-cli pkgs.openssh ]}
  '';
  meta = nix-secrets.meta // {
    description = "nix-secrets with opt-in age and 1Password recipient support";
  };
}
