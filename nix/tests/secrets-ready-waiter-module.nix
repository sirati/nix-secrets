# Waiters may publish their waiting state and wait forever; the reporter
# fails (exit 2 is not success) once a waiter exceeds reportAfterSeconds,
# runs from a timer, and no unit depends on it.
{
  nixpkgs,
  module,
  system,
}:
let
  lib = nixpkgs.lib;
  evaluate =
    extra:
    (nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        module
        extra
        {
          networking.hostName = "host";
          system.stateVersion = "25.11";
          services.nixSecrets = {
            enable = true;
            defaultRecipientPublicKeys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILXG+KfyD7ATstszFLEBBeA+dfXXoD8fxhLcSjtoiqGP"
            ];
            services.mail = {
              consumerUnits = [ "consumer.service" ];
              secrets.password.destination = {
                path = "/persistent/secrets/mail/service/password";
                category = "service";
                owner = "root";
                group = "root";
                mode = "0400";
              };
            };
          };
          services.secretsReadyWaiter.enable = true;
          systemd.services.consumer.script = "true";
        }
      ];
    }).config;
  config = evaluate { };
  custom = evaluate { services.secretsReadyWaiter.reportAfterSeconds = 60; };
  services = config.systemd.services;
  waiter = services.secrets-ready-waiter-mail.serviceConfig;
  reporter = services.nix-secrets-waiting;
  timer = config.systemd.timers.nix-secrets-waiting;
  dependsOnReporter =
    name: unit:
    name != "nix-secrets-waiting"
    && builtins.any (lib.hasPrefix "nix-secrets-waiting.") (
      (unit.requires or [ ])
      ++ (unit.requisite or [ ])
      ++ (unit.bindsTo or [ ])
      ++ (unit.after or [ ])
      ++ (unit.wants or [ ])
    );
  successStatus = toString (reporter.serviceConfig.SuccessExitStatus or "");
in
assert waiter.Type == "oneshot";
assert waiter.NotifyAccess == "main";
assert waiter.TimeoutStartSec == "infinity";
assert builtins.elem "AF_UNIX" waiter.RestrictAddressFamilies;
assert builtins.elem "secrets-ready-waiter-mail.service" services.consumer.requires;
assert reporter.serviceConfig.Type == "oneshot";
assert reporter.serviceConfig.DynamicUser;
assert lib.hasInfix "--report-waiting --systemctl /nix/store/" reporter.serviceConfig.ExecStart;
assert lib.hasSuffix "--after 900" reporter.serviceConfig.ExecStart;
assert lib.hasSuffix "--after 60"
  custom.systemd.services.nix-secrets-waiting.serviceConfig.ExecStart;
assert !(builtins.elem "2" (lib.splitString " " successStatus));
assert !(reporter.serviceConfig ? TimeoutStartSec);
assert reporter.wantedBy or [ ] == [ ];
assert timer.wantedBy == [ "timers.target" ];
assert timer.timerConfig.OnBootSec == "5min";
assert timer.timerConfig.OnUnitInactiveSec == "5min";
assert
  !(builtins.any (name: dependsOnReporter name services.${name}) (builtins.attrNames services));
true
