# Consumers of a defaulted public-info leaf require and start after its
# installer; a leaf without a default adds no edge.
{ nixpkgs, module, system }:
let
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  leaf = id: extra: {
    kind = "public-info";
    sharedPublicId = id;
    expectedSshHost = "backup.example";
    expectedSshPort = 23;
    consumerUnits = [ "reader.service" ];
    destination = {
      path = "/persistent/public-info/${id}";
      category = "public-info";
      owner = "root";
      group = "root";
      mode = "0644";
      contentType = "ssh-known-hosts";
    };
  } // extra;
  config = (nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [ module {
      networking.hostName = "host";
      system.stateVersion = "25.11";
      services.nixSecrets = {
        enable = true;
        defaultRecipientPublicKeys = [ key ];
        services.backup.secrets = {
          known-hosts = leaf "backup/known-hosts" {
            installDefaultIfMissing = true;
            defaultValue = "[backup.example]:23 ${key}\n";
          };
          optional-hosts = leaf "backup/optional-hosts" { optional = true; } // {
            consumerUnits = [ "other.service" ];
          };
        };
      };
      systemd.services.reader.script = "true";
      systemd.services.other.script = "true";
    } ];
  }).config;
  installer = "nix-secrets-public-default-${builtins.substring 0 16
    (builtins.hashString "sha256" "host.services.backup.known-hosts")}";
  edges = unit: config.systemd.services.${unit}.requires ++ config.systemd.services.${unit}.after;
in
assert config.systemd.services ? ${installer};
assert builtins.elem "${installer}.service" config.systemd.services.reader.requires;
assert builtins.elem "${installer}.service" config.systemd.services.reader.after;
assert !(builtins.any (nixpkgs.lib.hasPrefix "nix-secrets-public-default-") (edges "other"));
true
