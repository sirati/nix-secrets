# Optional leaves stay deployable but never add a service readiness gate.
{ nixpkgs, module, system }:
let
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  make = optional: nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [ module {
      networking.hostName = "host";
      system.stateVersion = "25.11";
      services.nixSecrets = {
        enable = true;
        defaultRecipientPublicKeys = [ key ];
        services.app = {
          consumerUnits = [ "app.service" ];
          secrets.password = {
            inherit optional;
            valueType = "password";
            destination = {
              path = "/persistent/secrets/app/service/password";
              category = "service";
              owner = "root";
              group = "root";
              mode = "0400";
            };
          };
        };
      };
      services.secretsReadyWaiter.enable = true;
    } ];
  };
  optional = (make true).config;
  required = (make false).config;
in
assert optional.services.nixSecrets.evaluated.host.services.app.password.optional;
assert !(optional.systemd.services ? secrets-ready-waiter-app);
assert required.systemd.services ? secrets-ready-waiter-app;
assert builtins.elem "secrets-ready-waiter-app.service" required.systemd.services.app.requires;
assert optional.system.build.nixSecretsManifest != null;
true
