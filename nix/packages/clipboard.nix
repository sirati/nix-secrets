{
  lib,
  symlinkJoin,
  makeWrapper,
  wl-clipboard,
  nix-secrets,
}:

symlinkJoin {
  name = "nix-secrets-clipboard";
  paths = [ nix-secrets ];
  nativeBuildInputs = [ makeWrapper ];
  postBuild = ''
    wrapProgram $out/bin/nix-secrets \
      --prefix PATH : ${lib.makeBinPath [ wl-clipboard ]}
  '';
}
