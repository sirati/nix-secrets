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
      ;
    deployment = lib.filterAttrs (_: value: value != null) cfg.deployment;
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
  requiredLeaves = secretsLib.requiredForInstallLeaves evaluated;
  requiredEntries =
    requiredLeaves
    ++ map (identifier: {
      inherit identifier;
      leaf = (lib.findFirst (entry: entry.identifier == identifier) { leaf = null; } requiredLeaves).leaf;
    }) cfg.requiredBeforeInstall;
  missingBeforeInstall = lib.unique (secretsLib.missingBeforeInstall cfg.storeFile requiredEntries);
  serviceGroups = builtins.removeAttrs evaluatedHost [ "metadata" ];
  leaves = builtins.filter (leaf: !(secretsLib.isOperatorLeaf leaf)) (
    lib.concatMap (
      services: lib.concatMap secretsLib.collectLeaves (builtins.attrValues services)
    ) (builtins.attrValues serviceGroups)
  );
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
      if secretsLib.isLeaf node then
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
  # The installed default: the store's record, else the leaf's own
  # defaultValue, so a consumer that pins the value in Nix needs no record.
  defaultOf =
    entry:
    if builtins.hasAttr entry.leaf.sharedPublicId publicRecords then
      publicRecords.${entry.leaf.sharedPublicId}.value
    else
      entry.leaf.defaultValue or null;
  publicDefaults = builtins.filter (entry: defaultOf entry != null) publicEntries;
  defaultUnit =
    entry:
    let
      hash = builtins.substring 0 16 (builtins.hashString "sha256" entry.identifier);
      value = defaultOf entry;
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
      publishHostIdentityTo = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Public-info leaf receiving this host's authenticated SSH identity during deployment preparation. Replacing an existing value requires separate client consent.";
      };
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
      identityPublicKeys = lib.mkOption {
        type = lib.types.listOf (lib.types.strMatching "[^\n]+");
        default =
          if cfg.forwarder.enable or false then
            map (lib.removeSuffix "\n") cfg.forwarder.authorizedKeys
          else
            [ ];
        defaultText = lib.literalExpression "the forwarder's authorizedKeys when it is enabled";
        description = ''
          The public keys the deploying frontend offers, and the only ones. They
          must be the keys the forwarder authorizes; the frontend asks its
          ssh-agent to sign with one of them, so an agent holding many keys is
          not cut off by sshd's MaxAuthTries before reaching the right one.
        '';
      };
      protocolVersion = lib.mkOption {
        type = lib.types.nullOr lib.types.ints.positive;
        default = cfg.receiver.package.passthru.deploymentProtocolVersion or null;
        defaultText = lib.literalExpression "the receiver package's deployment protocol";
        description = ''
          The deployment protocol this host's receiver speaks, from the
          package it is built with. The frontend checks before connecting
          that the host supports every feature a deployment uses; values that
          need a newer receiver are listed as not deployed. null: unknown,
          checked only after connecting.
        '';
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
    storeFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = cfg.publicInfoInventoryFile;
      defaultText = lib.literalExpression "config.services.nixSecrets.publicInfoInventoryFile";
      description = ''
        The committed nix-secrets.toml, read purely at evaluation to check that
        every value required before install is present.
      '';
    };
    requiredBeforeInstall = lib.mkOption {
      type = lib.types.listOf (lib.types.strMatching "[^.]+[.][^.]+[.].+");
      default = [ ];
      example = [ "ns1.services.nmbl.generation-key" ];
      description = ''
        Further identifiers, as HOST.NAMESPACE.SERVICE.PATH, that must have a
        value in storeFile before this host is installed, in addition to this
        host's leaves marked requiredForInstall. Use it for a value declared
        on another host or consumed through operatorPublicKey.
      '';
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
      {
        assertion = requiredEntries == [ ] || cfg.storeFile != null;
        message = "services.nixSecrets.storeFile must name the committed nix-secrets.toml to check values required before install";
      }
    ]
    ++ lib.optionals (cfg.storeFile != null) (
      map (identifier: {
        assertion = false;
        message = secretsLib.missingBeforeInstallMessage identifier;
      }) missingBeforeInstall
    );
    services.nixSecrets.evaluated = evaluated;
    # Operator-only leaves never reach the host.
    system.build.nixSecretsManifest = pkgs.writeText "nix-secrets-${cfg.hostName}.json" (
      builtins.toJSON (
        builtins.mapAttrs (
          _: host:
          builtins.mapAttrs (
            group: services:
            if group == "metadata" then services else secretsLib.withoutOperatorLeaves services
          ) host
        ) evaluated
      )
    );
    environment.etc."nix-secrets/manifest.json".source = config.system.build.nixSecretsManifest;
    systemd.services = lib.listToAttrs (map defaultUnit publicDefaults);
  };
}
