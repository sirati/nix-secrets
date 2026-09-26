# Test-only: installs a mock value for every leaf of this host's manifest.
#
# The values go through `secret-deploy --mock-install`, which validates and
# publishes them with the same code as a real deployment, so ownership,
# modes, generations, service links and the readiness waiters behave as in
# production. Mock values never touch nix-secrets.toml or the backend.
# Explicit values are written to the world-readable Nix store and must be
# non-secret test data.
#
# Guard: enabling the mock requires
# `iUnderstandThisIsATestOnlyConfiguration = true`. The qemu-vm or test
# instrumentation modules are deliberately not required, since consumers
# also test custom VM setups (such as a real disk image booted under
# SeaBIOS) that import neither. A mocked system is marked by the
# `nix-secrets-mock` NixOS tag, an evaluation warning, and
# /etc/nix-secrets/MOCK-SECRETS-TEST-ONLY.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nixSecrets;
  mock = cfg.mock;
  secretsLib = import ../lib.nix { inherit lib; };

  hostTree = if cfg.enable then cfg.evaluated.${cfg.hostName} else { };
  namespaces = builtins.removeAttrs hostTree [ "metadata" ];
  collect =
    prefix: tree:
    lib.concatMap (
      name:
      let
        node = tree.${name};
        identifier = "${prefix}.${name}";
      in
      if !builtins.isAttrs node then
        [ ]
      else if secretsLib.isLeaf node then
        lib.optional (!(secretsLib.isOperatorLeaf node)) {
          inherit identifier;
          leaf = node;
        }
      else
        collect identifier node
    ) (builtins.attrNames tree);
  deployable = lib.concatMap (
    namespace:
    lib.concatMap (service: collect "${cfg.hostName}.${namespace}.${service}" namespaces.${namespace}.${service}) (
      builtins.attrNames namespaces.${namespace}
    )
  ) (builtins.attrNames namespaces);
  deployableIds = map (entry: entry.identifier) deployable;

  # "HOST.NAMESPACE.SERVICE.PATH" names any leaf of this host; any other key
  # is "<service>.<path>" of a machine service.
  isFullIdentifier =
    key:
    let
      parts = lib.splitString "." key;
    in
    builtins.length parts >= 4
    && builtins.head parts == cfg.hostName
    && builtins.hasAttr (builtins.elemAt parts 1) namespaces;
  resolveKey = key: if isFullIdentifier key then key else "${cfg.hostName}.services.${key}";
  resolved = lib.mapAttrs' (key: value: lib.nameValuePair (resolveKey key) value) mock.values;
  unresolved = builtins.filter (key: !(builtins.elem (resolveKey key) deployableIds)) (
    builtins.attrNames mock.values
  );
  duplicateKeys = builtins.length (builtins.attrNames resolved) != builtins.length (builtins.attrNames mock.values);

  valuesFile = pkgs.writeText "nix-secrets-mock-values-${cfg.hostName}.json" (builtins.toJSON resolved);
  # Same names as the public-default units in schema.nix; ordering after a
  # unit that does not exist is a no-op.
  publicDefaultUnits = map (
    entry: "nix-secrets-public-default-${builtins.substring 0 16 (builtins.hashString "sha256" entry.identifier)}.service"
  ) (builtins.filter (entry: entry.leaf.installDefaultIfMissing or false) deployable);
  consumers = lib.unique (lib.concatMap (entry: entry.leaf.consumerUnits or [ ]) deployable);
in
{
  options.services.nixSecrets.mock = {
    enable = lib.mkEnableOption ''
      TEST-ONLY mock secrets: every leaf of this host is installed with a
      mock value at boot, without the backend or nix-secrets.toml. Requires
      iUnderstandThisIsATestOnlyConfiguration'';
    iUnderstandThisIsATestOnlyConfiguration = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Must be true whenever mock.enable is set. Mock values replace every
        real secret of the host, so a production configuration must never
        enable the mock.
      '';
    };
    values = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        "postgres.password" = "test-password";
        "machine.user-alice-services.mail.token" = "test-token";
      };
      description = ''
        Explicit mock values, keyed by "<service>.<leaf path>" for a machine
        service or by the full identifier "HOST.NAMESPACE.SERVICE.PATH". Each
        key must name a deployable leaf of this host. A key naming a derived
        leaf gives its source value, which is framed like a real one. These
        values are world-readable in the Nix store: use non-secret test data.
      '';
    };
    generateRest = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Generate a mock value for every leaf without an explicit one. When
        false, a leaf without an explicit value fails the mock unit, which
        lists every missing leaf.
      '';
    };
  };

  config = lib.mkIf mock.enable {
    assertions = [
      {
        assertion = mock.iUnderstandThisIsATestOnlyConfiguration;
        message = ''
          services.nixSecrets.mock.enable installs mock values in place of every
          real secret of this host. It is for test configurations only; set
          services.nixSecrets.mock.iUnderstandThisIsATestOnlyConfiguration = true
          in the test configuration to confirm.'';
      }
      {
        assertion = cfg.enable;
        message = "services.nixSecrets.mock requires services.nixSecrets.enable";
      }
      {
        assertion = unresolved == [ ];
        message = "services.nixSecrets.mock.values names no deployable leaf of ${cfg.hostName}: ${lib.concatStringsSep ", " unresolved} (operator-only leaves are never deployed)";
      }
      {
        assertion = !duplicateKeys;
        message = "services.nixSecrets.mock.values names the same leaf twice";
      }
    ];
    warnings = [
      "services.nixSecrets.mock is enabled: ${cfg.hostName} receives MOCK secrets. Never deploy this configuration to production."
    ];
    system.nixos.tags = [ "nix-secrets-mock" ];
    environment.etc."nix-secrets/MOCK-SECRETS-TEST-ONLY".text = ''
      This system was built with services.nixSecrets.mock enabled.
      Its secrets are mock test values, not real secrets.
    '';

    # The same roots the receiver creates, so the mock works without it.
    systemd.tmpfiles.rules = lib.mkIf cfg.enable [
      "d /persistent/secrets 0711 root root - -"
      "d /persistent/public-info 0711 root root - -"
    ];

    systemd.services.nix-secrets-mock-install = lib.mkIf cfg.enable {
      description = "Install TEST-ONLY mock nix-secrets values";
      wantedBy = [ "multi-user.target" ] ++ consumers;
      before = consumers;
      # Declared public defaults are real public information: let them
      # install first so the mock only fills what they leave unset.
      after = [
        "local-fs.target"
        "systemd-tmpfiles-setup.service"
      ]
      ++ publicDefaultUnits;
      unitConfig.RequiresMountsFor = [ "/persistent" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = lib.escapeShellArgs (
          [
            "${cfg.receiver.package}/bin/secret-deploy"
            "--mock-install"
            "--manifest"
            (toString config.system.build.nixSecretsManifest)
            "--values"
            (toString valuesFile)
          ]
          ++ lib.optional mock.generateRest "--generate-rest"
        );
        UMask = "0077";
        # The mock never contacts a backend or a Storage Box.
        PrivateNetwork = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ReadWritePaths = [
          "/persistent/secrets"
          "/persistent/public-info"
        ];
      };
    };
  };
}
