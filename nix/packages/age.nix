{
  lib,
  pkgs,
  makeWrapper,
  symlinkJoin,
  nix-secrets,
}:

symlinkJoin {
  name = "nix-secrets-with-age";
  paths = [ nix-secrets ];
  nativeBuildInputs = [ makeWrapper ];
  postBuild = ''
    wrapProgram "$out/bin/nix-secrets" \
      --prefix PATH : ${lib.makeBinPath [ pkgs.age pkgs.openssh ]}
  '';
  meta = nix-secrets.meta // {
    description = "nix-secrets with age and OpenSSH for identity-file use";
  };
}
