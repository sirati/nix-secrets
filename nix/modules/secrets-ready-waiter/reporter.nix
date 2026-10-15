# Surfaces secrets waiters that have been waiting too long: the reporter
# exits 2 and leaves nix-secrets-waiting.service failed, which the fault
# report sweep picks up. Nothing depends on it, so consumers never notice.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nixSecrets;
  waiter = config.services.secretsReadyWaiter;
in
{
  options.services.secretsReadyWaiter.reportAfterSeconds = lib.mkOption {
    type = lib.types.ints.positive;
    default = 900;
    description = ''
      Seconds a `secrets-ready-waiter-*` unit may wait for operator secrets
      before `nix-secrets-waiting.service` fails and names it. Waiters and
      their consumers keep waiting regardless; this only makes the wait
      visible.
    '';
  };

  config = lib.mkIf (cfg.enable && waiter.enable) {
    systemd.services.nix-secrets-waiting = {
      description = "Report secrets waiters waiting longer than ${toString waiter.reportAfterSeconds}s";
      serviceConfig = import ./hardening.nix // {
        Type = "oneshot";
        ExecStart = lib.escapeShellArgs [
          (lib.getExe waiter.package)
          "--report-waiting"
          "--systemctl"
          "${config.systemd.package}/bin/systemctl"
          "--after"
          (toString waiter.reportAfterSeconds)
        ];
      };
    };

    systemd.timers.nix-secrets-waiting = {
      description = "Periodically report secrets waiters that are still waiting";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "5min";
        OnUnitInactiveSec = "5min";
      };
    };
  };
}
