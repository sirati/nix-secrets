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
  # age-plugin-1p runs `op` through PATH. The 1Password desktop app accepts
  # only an `op` that is setgid onepassword-cli, such as the NixOS
  # programs._1password wrapper in /run/wrappers/bin. The bundled CLI is
  # therefore a PATH suffix: it never shadows that wrapper and only serves
  # hosts without one, for example with OP_SERVICE_ACCOUNT_TOKEN.
  postBuild = ''
    wrapProgram "$out/bin/nix-secrets" \
      --prefix PATH : ${lib.makeBinPath [ ageWithOnePassword pkgs.openssh ]} \
      --suffix PATH : ${lib.makeBinPath [ pkgs._1password-cli ]}
  '';
  meta = nix-secrets.meta // {
    description = "nix-secrets with opt-in age and 1Password recipient support";
  };
}
