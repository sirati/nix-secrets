# The schema module fails evaluation, naming the identifier, while a value
# required before install is missing from the committed store.
{ nixpkgs, module, system }:
let
  inherit (nixpkgs) lib;
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  failed =
    store: extra:
    let
      system' = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          module
          {
            networking.hostName = "host";
            system.stateVersion = "25.11";
            boot.loader.grub.enable = false;
            fileSystems."/" = { device = "/dev/vda"; fsType = "ext4"; };
            services.nixSecrets = {
              enable = true;
              defaultRecipientPublicKeys = [ key ];
              storeFile = store;
              requiredBeforeInstall = extra;
              services.nmbl.secrets.generation-key = {
                kind = "operator";
                requiredForInstall = true;
                generator.installable = "github:example/tool#keygen";
              };
            };
          }
        ];
      };
    in
    map (assertion: assertion.message) (
      builtins.filter (assertion: !assertion.assertion) system'.config.assertions
    );
  unset = builtins.toFile "unset.toml" "";
  set = builtins.toFile "set.toml" ''
    [secrets."host.services.nmbl.generation-key"]
    age_ciphertext = "YWdl"
    public_key = "AQJwdWJsaWM="
  '';
  message = id: "generate/enter ${id} in the nix-secrets TUI first: it is required before this host can be installed";
in
assert failed (toString unset) [ ] == [ (message "host.services.nmbl.generation-key") ];
assert failed (toString set) [ ] == [ ];
assert failed (toString set) [ "other.services.dns.key" ] == [ (message "other.services.dns.key") ];
# Required values need a store to be checked against.
assert failed null [ ] == [
  "services.nixSecrets.storeFile must name the committed nix-secrets.toml to check values required before install"
];
true
