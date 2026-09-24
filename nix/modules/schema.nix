{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nixSecrets;
  secretsLib = import ../lib.nix { inherit lib; };

  serviceType = lib.types.submodule {
    options = {
      displayPath = lib.mkOption {
        type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9_-]+");
        default = [ ];
        example = [
          "forgejo"
          "backup"
        ];
        description = "Presentation-only tree path. It does not change secret identifiers or readiness gates.";
      };
      recipientPublicKeys = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.str);
        default = null;
        description = "SSH public keys overriding the inherited recipients.";
      };
      recipientNames = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.str);
        default = null;
        description = "Named encryption recipients overriding the inherited names.";
      };
      consumerUnits = lib.mkOption {
        type = lib.types.listOf (lib.types.strMatching ".+[.]service");
        default = [ ];
        example = [ "postgresql.service" ];
        description = "System units which may start only after these secrets exist.";
      };
      secrets = lib.mkOption {
        type = lib.types.attrs;
        description = ''
          A nested tree. A leaf has either destination or generatedSecret. Any
          branch may set _recipientPublicKeys to override recipients below it.
        '';
      };
    };
  };

  serviceValue =
    value:
    value
    // lib.optionalAttrs (value.recipientPublicKeys == null) {
      recipientPublicKeys = cfg.defaultRecipientPublicKeys;
    }
    // lib.optionalAttrs (value.recipientNames == null) {
      recipientNames = if value.recipientPublicKeys == null then cfg.defaultRecipientNames else [ ];
    };

  normalizeServiceSet = values: lib.mapAttrs (_: serviceValue) values;
  evaluated = secretsLib.normalizeHost {
    inherit (cfg)
      hostName
      socketPath
      defaultRecipientPublicKeys
      recipientPublicKeys
      defaultRecipientNames
      deployment
      ;
    services = normalizeServiceSet cfg.services;
    userServices = lib.mapAttrs (_: normalizeServiceSet) cfg.userServices;
    serviceDisplayPaths = {
      services = lib.mapAttrs (_: service: service.displayPath) (
        lib.filterAttrs (_: service: service.displayPath != [ ]) cfg.services
      );
    }
    // lib.mapAttrs' (
      user: services:
      lib.nameValuePair "user-${user}-services" (
        lib.mapAttrs (_: service: service.displayPath) (
          lib.filterAttrs (_: service: service.displayPath != [ ]) services
        )
      )
    ) cfg.userServices;
  };
  evaluatedHost = evaluated.${cfg.hostName};
  serviceGroups = builtins.removeAttrs evaluatedHost [ "metadata" ];
  leaves = lib.concatMap (
    services: lib.concatMap secretsLib.collectLeaves (builtins.attrValues services)
  ) (builtins.attrValues serviceGroups);
  destinationPaths = map (
    leaf:
    if leaf.kind or null == "generated" then leaf.generatedSecret.output.path else leaf.destination.path
  ) leaves;
  collectPublic =
    prefix: tree:
    lib.concatMap (
      name:
      let
        node = tree.${name};
        identifier = "${prefix}.${name}";
      in
      if node ? destination || node ? generatedSecret then
        lib.optional ((node.kind or "secret") == "public-info" && (node.installDefaultIfMissing or false)) {
          inherit identifier;
          leaf = node;
        }
      else
        collectPublic identifier node
    ) (builtins.attrNames tree);
  publicEntries = lib.concatMap (
    namespace:
    lib.concatMap (
      service:
      collectPublic "${cfg.hostName}.${namespace}.${service}" serviceGroups.${namespace}.${service}
    ) (builtins.attrNames serviceGroups.${namespace})
  ) (builtins.attrNames serviceGroups);
  inventory =
    if cfg.publicInfoInventoryFile == null || !(builtins.pathExists cfg.publicInfoInventoryFile) then
      { }
    else
      builtins.fromTOML (builtins.readFile cfg.publicInfoInventoryFile);
  publicRecords = inventory.public_info or { };
  publicDefaults = builtins.filter (
    entry: builtins.hasAttr entry.leaf.sharedPublicId publicRecords
  ) publicEntries;
  defaultUnit =
    entry:
    let
      hash = builtins.substring 0 16 (builtins.hashString "sha256" entry.identifier);
      record = publicRecords.${entry.leaf.sharedPublicId};
      value = record.value;
      source = pkgs.writeText "nix-secrets-public-default-${hash}" value;
    in
    lib.nameValuePair "nix-secrets-public-default-${hash}" {
      description = "Install declared public information if absent";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      unitConfig.RequiresMountsFor = [ "/persistent/public-info" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.escapeShellArgs [
          "${cfg.receiver.package}/bin/secret-deploy"
          "--install-public-default"
          "--manifest"
          (toString config.system.build.nixSecretsManifest)
          "--identifier"
          entry.identifier
          "--source"
          (toString source)
          "--version"
          (builtins.hashString "sha256" value)
        ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/persistent/public-info" ];
        UMask = "0022";
      };
    };
in
{
  options.services.nixSecrets = {
    enable = lib.mkEnableOption "declarative secret inventory and readiness gates";
    hostName = lib.mkOption {
      type = lib.types.str;
      default = config.networking.hostName;
      defaultText = lib.literalExpression "config.networking.hostName";
    };
    socketPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/nix-secrets/backend.sock";
      description = "Backend Unix socket advertised in the evaluated inventory.";
    };
    deployment = {
      host = lib.mkOption {
        type = lib.types.strMatching "[^[:space:]]+";
        default = cfg.hostName;
        defaultText = lib.literalExpression "config.services.nixSecrets.hostName";
        description = "SSH host authenticated by the deploying frontend.";
      };
      destination = lib.mkOption {
        type = lib.types.strMatching "[^-[:space:]][^[:space:]]*";
        default = "nix-secrets-forward@${cfg.hostName}";
        defaultText = lib.literalExpression ''"nix-secrets-forward@''${config.services.nixSecrets.hostName}"'';
        description = "OpenSSH destination used for direct target deployment.";
      };
      port = lib.mkOption {
        type = lib.types.ints.between 1 65535;
        default = 22;
      };
    };
    defaultRecipientPublicKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Default SSH public keys used to wrap secret encryption keys.";
    };
    recipientPublicKeys = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Named SSH public keys used as encryption recipients.";
    };
    defaultRecipientNames = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Default names from recipientPublicKeys for secret encryption.";
    };
    publicInfoInventoryFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional absolute TOML path read at evaluation; only selected public_info values enter generated defaults.";
    };
    services = lib.mkOption {
      type = lib.types.attrsOf serviceType;
      default = { };
      description = "Machine service secret definitions.";
    };
    userServices = lib.mkOption {
      type = lib.types.attrsOf (lib.types.attrsOf serviceType);
      default = { };
      description = "Secret definitions keyed by user and then service.";
    };
    evaluated = lib.mkOption {
      type = lib.types.attrs;
      readOnly = true;
      description = "Normalized, non-secret inventory consumed by the manager.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.length destinationPaths == builtins.length (lib.unique destinationPaths);
        message = "services.nixSecrets secret destinations must be globally unique";
      }
    ];
    services.nixSecrets.evaluated = evaluated;
    system.build.nixSecretsManifest = pkgs.writeText "nix-secrets-${cfg.hostName}.json" (
      builtins.toJSON evaluated
    );
    environment.etc."nix-secrets/manifest.json".source = config.system.build.nixSecretsManifest;
    systemd.services = lib.listToAttrs (map defaultUnit publicDefaults);
  };
}
