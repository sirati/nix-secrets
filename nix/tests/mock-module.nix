# Evaluation-level guard of services.nixSecrets.mock: it cannot be enabled
# without the explicit test-only acknowledgement, every mock key must name a
# deployable leaf of the host, and a mocked system is visibly marked.
{
  nixpkgs,
  module,
  system,
}:
let
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  evaluate =
    mock:
    (nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        module
        {
          networking.hostName = "host";
          system.stateVersion = "25.11";
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "/dev/vda";
            fsType = "ext4";
          };
          services.nixSecrets = {
            enable = true;
            defaultRecipientPublicKeys = [ key ];
            services.app.secrets.token.destination = {
              path = "/persistent/secrets/app/service/token";
              category = "service";
              owner = "root";
              group = "root";
              mode = "0400";
            };
            userServices.alice.mail.secrets.token.destination = {
              path = "/persistent/secrets/mail/service/token";
              category = "service";
              owner = "root";
              group = "root";
              mode = "0400";
            };
            services.signing.secrets.generation-key = {
              kind = "operator";
              generator.installable = "github:example/tool#keygen";
            };
            inherit mock;
          };
        }
      ];
    }).config;
  failed =
    mock:
    map (assertion: assertion.message) (
      builtins.filter (assertion: !assertion.assertion) (evaluate mock).assertions
    );
  acknowledged = {
    enable = true;
    iUnderstandThisIsATestOnlyConfiguration = true;
  };
  unknown =
    ids:
    "services.nixSecrets.mock.values names no deployable leaf of host: ${builtins.concatStringsSep ", " ids} (operator-only leaves are never deployed)";
  ok = evaluate (
    acknowledged
    // {
      values = {
        "app.token" = "a";
        "host.user-alice-services.mail.token" = "b";
      };
    }
  );
in
# Enabling the mock without the acknowledgement fails evaluation.
assert builtins.length (failed { enable = true; }) == 1;
assert nixpkgs.lib.hasInfix "iUnderstandThisIsATestOnlyConfiguration" (
  builtins.head (failed { enable = true; })
);
# Disabled, the mock adds nothing.
assert failed { } == [ ];
assert !(builtins.elem "nix-secrets-mock" (evaluate { }).system.nixos.tags);
assert !((evaluate { }).systemd.services ? nix-secrets-mock-install);
# Acknowledged, valid keys evaluate and the system is marked.
assert failed (acknowledged // { values."app.token" = "a"; }) == [ ];
assert builtins.elem "nix-secrets-mock" ok.system.nixos.tags;
assert nixpkgs.lib.hasInfix "nix-secrets-mock" ok.system.nixos.label;
assert ok.environment.etc ? "nix-secrets/MOCK-SECRETS-TEST-ONLY";
assert builtins.any (nixpkgs.lib.hasInfix "MOCK secrets") ok.warnings;
assert ok.systemd.services ? nix-secrets-mock-install;
# Unknown keys and operator-only leaves are refused.
assert
  failed (
    acknowledged
    // {
      values = {
        "app.missing" = "x";
        "signing.generation-key" = "x";
        "host.user-alice-services.mail.nope" = "x";
      };
    }
  ) == [
    (unknown [
      "app.missing"
      "host.user-alice-services.mail.nope"
      "signing.generation-key"
    ])
  ];
true
