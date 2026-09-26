{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nixSecrets.receiver;
  secrets = config.services.nixSecrets;
  treeHasGeneratedSecret =
    tree:
    lib.any (
      name:
      let
        node = tree.${name};
      in
      builtins.isAttrs node && (node ? generatedSecret || treeHasGeneratedSecret node)
    ) (builtins.attrNames tree);
  servicesHaveGeneratedSecret =
    services: lib.any (service: treeHasGeneratedSecret service.secrets) (builtins.attrValues services);
  hasGeneratedSecrets =
    servicesHaveGeneratedSecret secrets.services
    || lib.any servicesHaveGeneratedSecret (builtins.attrValues secrets.userServices);
in
{
  options.services.nixSecrets.receiver = {
    enable = lib.mkEnableOption "socket-activated atomic secret deployment receiver";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../packages/default.nix { };
      defaultText = lib.literalExpression "the bundled nix-secrets package";
    };
    socketPath = lib.mkOption {
      type = lib.types.strMatching "/.*";
      default = "/run/nix-secrets/deployer.sock";
    };
    accessGroup = lib.mkOption {
      type = lib.types.str;
      default = "nix-secrets-deploy";
      description = "Group allowed to reach the fixed deployment socket.";
    };
    auditGroup = lib.mkOption {
      type = lib.types.str;
      default = "root";
      description = "Group allowed to read deployment audit events without accessing secrets.";
    };
  };

  config = lib.mkIf (secrets.enable && cfg.enable) {
    users.groups.${cfg.accessGroup} = { };

    systemd.sockets.nix-secrets-deployer = {
      description = "Nix secrets deployment receiver socket";
      wantedBy = [ "sockets.target" ];
      listenStreams = [ cfg.socketPath ];
      socketConfig = {
        Accept = true;
        DirectoryMode = "0750";
        SocketMode = "0660";
        SocketUser = "root";
        SocketGroup = cfg.accessGroup;
        RemoveOnStop = true;
      };
    };

    systemd.services."nix-secrets-deployer@" = {
      description = "Atomic nix-secrets deployment transaction";
      serviceConfig = {
        Type = "oneshot";
        TimeoutStartSec = "20min";
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/secret-deploy"
          "--manifest"
          (toString config.system.build.nixSecretsManifest)
          "--age"
          "${pkgs.age}/bin/age"
          "--audit-file"
          "/run/nix-secrets/audit/%i.json"
          "--audit-group"
          cfg.auditGroup
        ];
        UMask = "0077";
        CapabilityBoundingSet = [
          "CAP_CHOWN"
          "CAP_DAC_OVERRIDE"
          "CAP_FOWNER"
        ];
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        ReadWritePaths = [
          "/persistent/secrets"
          "/persistent/public-info"
          "/run/nix-secrets/audit"
        ];
        RestrictAddressFamilies = [
          "AF_UNIX"
        ]
        ++ lib.optionals hasGeneratedSecrets [
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@mount"
          "~@reboot"
          "~@swap"
        ];
      };
    };

    systemd.tmpfiles.rules = [
      "d /run/nix-secrets 0711 root root - -"
      "d /run/nix-secrets/audit 0750 root ${cfg.auditGroup} - -"
      "d /persistent/secrets 0711 root root - -"
      "d /persistent/public-info 0711 root root - -"
      "d /persistent/secrets/.generations 0711 root root - -"
    ];
  };
}
