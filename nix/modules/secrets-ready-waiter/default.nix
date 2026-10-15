{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nixSecrets;
  waiter = config.services.secretsReadyWaiter;
  secretsLib = import ../../lib.nix { inherit lib; };

  machineEntries = lib.mapAttrsToList (name: value: {
    id = name;
    tree = cfg.evaluated.${cfg.hostName}.services.${name};
  }) cfg.services;
  userEntries = lib.concatLists (
    lib.mapAttrsToList (
      user: services:
      lib.mapAttrsToList (name: value: {
        id = "user-${user}-${name}";
        tree = cfg.evaluated.${cfg.hostName}."user-${user}-services".${name};
      }) services
    ) cfg.userServices
  );
  entries = machineEntries ++ userEntries;

  unitName = id: "secrets-ready-waiter-${lib.replaceStrings [ "." "@" "/" ] [ "-" "-" "-" ] id}";
  entryData =
    entry:
    let
      leaves = builtins.filter (
        leaf: leaf.kind != "public-info" && leaf.kind != "operator" && !(leaf.optional or false)
      ) (secretsLib.collectLeaves entry.tree);
      destinations = map (
        leaf: if leaf.kind == "generated" then leaf.generatedSecret.output else leaf.destination
      ) leaves;
      paths = map (destination: destination.path) destinations;
      expected = map (destination: {
        inherit (destination)
          path
          owner
          group
          mode
          ;
        runtime_readers = map (reader: {
          account = reader.account;
          uid_offset = reader.uidOffset;
        }) (waiter.runtimeReaders.${destination.path} or [ ]);
        acl_program = "${pkgs.acl}/bin/getfacl";
      }) destinations;
    in
    entry
    // {
      inherit leaves paths;
      consumers = lib.unique (lib.concatMap (leaf: leaf.consumerUnits) leaves);
      manifest = pkgs.writeText "${unitName entry.id}-manifest.json" (builtins.toJSON expected);
    };
  activeEntries = builtins.filter (entry: entry.paths != [ ]) (map entryData entries);

  waiterUnits = lib.listToAttrs (
    map (
      entry:
      lib.nameValuePair (unitName entry.id) {
        description = "Wait for persistent secrets required by ${entry.id}";
        after = [
          "local-fs.target"
          "nix-secrets-recover.service"
        ];
        serviceConfig = import ./hardening.nix // {
          Type = "oneshot";
          RemainAfterExit = true;
          # Status updates ("still waiting for …") come from the waiter itself.
          NotifyAccess = "main";
          ExecStart = "${lib.getExe waiter.package} ${entry.manifest}";
          # The operator may need hours to deploy; waiting is never a failure.
          TimeoutStartSec = "infinity";
          ReadOnlyPaths = [ "/persistent/secrets" ];
        };
      }
    ) activeEntries
  );

  consumerEdges = lib.mkMerge (
    lib.concatMap (
      entry:
      map (consumer: {
        ${lib.removeSuffix ".service" consumer} = {
          requires = [ "${unitName entry.id}.service" ];
          after = [ "${unitName entry.id}.service" ];
        };
      }) entry.consumers
    ) activeEntries
  );
in
{
  imports = [ ./reporter.nix ];

  options.services.secretsReadyWaiter = {
    enable = lib.mkEnableOption "per-service persistent-secret readiness gates";
    runtimeReaders = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.listOf (
          lib.types.submodule {
            options = {
              account = lib.mkOption {
                type = lib.types.str;
                description = "Account whose /etc/subuid range contains the reader.";
              };
              uidOffset = lib.mkOption {
                type = lib.types.ints.unsigned;
                description = "Offset of the reader UID inside that subordinate range.";
              };
            };
          }
        )
      );
      default = { };
      description = "Exact subordinate-UID readers permitted after runtime ACL preparation, keyed by secret destination.";
    };
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../../packages/secrets-ready-waiter.nix { };
      defaultText = lib.literalExpression "the bundled secrets-ready-waiter";
      description = "Package providing the secrets-ready-waiter binary (waiter and reporter).";
    };
  };

  config = lib.mkIf (cfg.enable && waiter.enable) {
    systemd.tmpfiles.rules = [ "d /persistent/secrets 0711 root root - -" ];
    systemd.services = lib.mkMerge [
      waiterUnits
      consumerEdges
    ];
  };
}
