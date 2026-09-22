{ config, lib, pkgs, ... }:

let
  cfg = config.services.nixSecrets;
  secretsLib = import ../lib.nix { inherit lib; };

  serviceType = lib.types.submodule {
    options = {
      recipientPublicKeys = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.str);
        default = null;
        description = "SSH public keys overriding the inherited recipients.";
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

  serviceValue = value:
    value // lib.optionalAttrs (value.recipientPublicKeys == null) {
      recipientPublicKeys = cfg.defaultRecipientPublicKeys;
    };

  normalizeServiceSet = values: lib.mapAttrs (_: serviceValue) values;
  evaluated = secretsLib.normalizeHost {
    inherit (cfg) hostName socketPath defaultRecipientPublicKeys deployment;
    services = normalizeServiceSet cfg.services;
    userServices = lib.mapAttrs (_: normalizeServiceSet) cfg.userServices;
  };
  evaluatedHost = evaluated.${cfg.hostName};
  serviceGroups = builtins.removeAttrs evaluatedHost [ "metadata" ];
  leaves = lib.concatMap (
    services: lib.concatMap secretsLib.collectLeaves (builtins.attrValues services)
  ) (builtins.attrValues serviceGroups);
  destinationPaths = map (
    leaf:
    if leaf.kind or null == "generated" then
      leaf.generatedSecret.output.path
    else
      leaf.destination.path
  ) leaves;
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
    assertions = [{
      assertion = builtins.length destinationPaths
        == builtins.length (lib.unique destinationPaths);
      message = "services.nixSecrets secret destinations must be globally unique";
    }];
    services.nixSecrets.evaluated = evaluated;
    system.build.nixSecretsManifest = pkgs.writeText "nix-secrets-${cfg.hostName}.json" (
      builtins.toJSON evaluated
    );
    environment.etc."nix-secrets/manifest.json".source =
      config.system.build.nixSecretsManifest;
  };
}
