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
  recover = "${cfg.package}/bin/secret-deploy --recover";
  # Shared by the deployment transaction and boot recovery.
  sandbox = {
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
    auditDirectory = lib.mkOption {
      type = lib.types.strMatching "/.*";
      default = "/run/nix-secrets/audit";
      description = "Root-owned directory for value-free deployment audit records.";
    };
    auditGroup = lib.mkOption {
      type = lib.types.str;
      default = "root";
      description = "Group allowed to read deployment audit events without accessing secrets.";
    };
    postDeployCommand = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Trusted executable in /nix/store to prepare newly published secrets before deployment succeeds. Runs inside the receiver sandbox with no protocol input or output.";
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
      serviceConfig = sandbox // {
        Type = "oneshot";
        # The transaction stays open while the operator reviews the values in
        # the TUI, and nothing may time out that wait. It ends with its
        # connection.
        TimeoutStartSec = "infinity";
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        ExecStart = lib.escapeShellArgs ([
          "${cfg.package}/bin/secret-deploy"
          "--manifest"
          (toString config.system.build.nixSecretsManifest)
          "--age"
          "${pkgs.age}/bin/age"
          "--audit-file"
          "${cfg.auditDirectory}/%i.json"
          "--audit-group"
          cfg.auditGroup
        ] ++ lib.optionals (cfg.postDeployCommand != null) [ "--post-deploy" cfg.postDeployCommand ]);
        # A killed transaction is finished or discarded right away.
        ExecStopPost = recover;
        ReadWritePaths = [
          "/persistent/secrets"
          "/persistent/public-info"
          cfg.auditDirectory
        ];
        RestrictAddressFamilies = [
          "AF_UNIX"
        ]
        ++ lib.optionals hasGeneratedSecrets [
          "AF_INET"
          "AF_INET6"
        ];
      };
    };

    # Finishes or discards a deployment interrupted by a crash, before any
    # consumer reads either root. The public default installers and the
    # readiness waiters order themselves after this unit.
    systemd.services.nix-secrets-recover = {
      description = "Finish or discard an interrupted nix-secrets deployment";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      unitConfig.RequiresMountsFor = [
        "/persistent/secrets"
        "/persistent/public-info"
      ];
      serviceConfig = sandbox // {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = recover;
        PrivateNetwork = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        # Absent roots have nothing to recover.
        ReadWritePaths = [
          "-/persistent/secrets"
          "-/persistent/public-info"
        ];
      };
    };

    systemd.tmpfiles.rules = [
      "d /run/nix-secrets 0711 root root - -"
      "d ${cfg.auditDirectory} 0750 root ${cfg.auditGroup} - -"
      "d /persistent/secrets 0711 root root - -"
      "d /persistent/public-info 0711 root root - -"
      "d /persistent/secrets/.generations 0711 root root - -"
    ];
  };
}
