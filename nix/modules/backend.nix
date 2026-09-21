{ config, lib, pkgs, ... }:

let
  cfg = config.services.nixSecrets.backend;
in
{
  options.services.nixSecrets.backend = {
    enable = lib.mkEnableOption "persistent nix-secrets ciphertext backend";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../packages/default.nix { };
      defaultText = lib.literalExpression "the bundled nix-secrets package";
    };
    user = lib.mkOption {
      type = lib.types.str;
      description = "Existing login user which owns the repository and backend socket.";
    };
    repository = lib.mkOption {
      type = lib.types.strMatching "/.*";
      description = "Repository containing nix-secrets.toml and nixSecretsSchemas.";
    };
    socketPath = lib.mkOption {
      type = lib.types.strMatching "/.*";
      default = config.services.nixSecrets.socketPath;
      defaultText = lib.literalExpression "config.services.nixSecrets.socketPath";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = builtins.hasAttr cfg.user config.users.users;
      message = "services.nixSecrets.backend.user must name a declared user";
    }];

    systemd.services.nix-secrets-backend = {
      description = "Nix secrets encrypted store backend";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      path = [ pkgs.nix ];
      serviceConfig = {
        User = cfg.user;
        RuntimeDirectory = "nix-secrets";
        RuntimeDirectoryMode = "0700";
        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/nix-secrets-backend"
          "--repository" (toString cfg.repository)
          "--socket" cfg.socketPath
        ];
        Restart = "on-failure";
        UMask = "0077";
        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      };
    };
  };
}
