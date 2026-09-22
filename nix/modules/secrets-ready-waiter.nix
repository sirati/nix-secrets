{ config, lib, pkgs, ... }:

let
  cfg = config.services.nixSecrets;
  waiter = config.services.secretsReadyWaiter;
  secretsLib = import ../lib.nix { inherit lib; };

  normalize = name: value:
    secretsLib.normalizeService cfg.defaultRecipientPublicKeys name (
      value // lib.optionalAttrs (value.recipientPublicKeys == null) {
        recipientPublicKeys = cfg.defaultRecipientPublicKeys;
      }
    );

  machineEntries = lib.mapAttrsToList (name: value: {
    id = name;
    tree = normalize name value;
  }) cfg.services;
  userEntries = lib.concatLists (lib.mapAttrsToList (user: services:
    lib.mapAttrsToList (name: value: {
      id = "user-${user}-${name}";
      tree = normalize name value;
    }) services
  ) cfg.userServices);
  entries = machineEntries ++ userEntries;

  unitName = id: "secrets-ready-waiter-${
    lib.replaceStrings [ "." "@" "/" ] [ "-" "-" "-" ] id
  }";
  entryData = entry:
    let
      leaves = secretsLib.collectLeaves entry.tree;
      destinations = map (
        leaf:
        if leaf.kind == "generated" then leaf.generatedSecret.output else leaf.destination
      ) leaves;
      paths = map (destination: destination.path) destinations;
      expected = map (destination: {
        inherit (destination) path owner group mode;
      }) destinations;
    in
    entry // {
      inherit leaves paths;
      consumers = lib.unique (lib.concatMap (leaf: leaf.consumerUnits) leaves);
      manifest = pkgs.writeText "${unitName entry.id}-manifest.json" (
        builtins.toJSON expected
      );
    };
  activeEntries = builtins.filter (entry: entry.paths != [ ]) (map entryData entries);

  waiterUnits = lib.listToAttrs (map (entry: lib.nameValuePair (unitName entry.id) {
    description = "Wait for persistent secrets required by ${entry.id}";
    after = [ "local-fs.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      DynamicUser = true;
      ExecStart = "${lib.getExe waiter.package} ${entry.manifest}";
      TimeoutStartSec = "infinity";
      CapabilityBoundingSet = "";
      DevicePolicy = "closed";
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      NoNewPrivileges = true;
      PrivateDevices = true;
      PrivateMounts = true;
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
      ReadOnlyPaths = [ "/persistent/secrets" ];
      RemoveIPC = true;
      RestrictAddressFamilies = [ "AF_UNIX" ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      SystemCallArchitectures = "native";
      SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      UMask = "0077";
    };
  }) activeEntries);

  consumerEdges = lib.mkMerge (lib.concatMap (entry:
    map (consumer: {
      ${lib.removeSuffix ".service" consumer} = {
        requires = [ "${unitName entry.id}.service" ];
        after = [ "${unitName entry.id}.service" ];
      };
    }) entry.consumers
  ) activeEntries);
in
{
  options.services.secretsReadyWaiter = {
    enable = lib.mkEnableOption "per-service persistent-secret readiness gates";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../packages/secrets-ready-waiter.nix { };
      defaultText = lib.literalExpression "the bundled secrets-ready-waiter";
    };
  };

  config = lib.mkIf (cfg.enable && waiter.enable) {
    systemd.tmpfiles.rules = [ "d /persistent/secrets 0711 root root - -" ];
    systemd.services = lib.mkMerge [ waiterUnits consumerEdges ];
  };
}
