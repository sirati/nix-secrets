{ config, lib, pkgs, ... }:

let
  cfg = config.services.nixSecrets.forwarder;
  receiver = config.services.nixSecrets.receiver;
  cleanKey = key: lib.removeSuffix "\n" key;
  forcedKey = key:
    ''restrict,command="nix-secrets-forward-deployer" ${cleanKey key}'';
  validKey = key:
    let
      cleaned = cleanKey key;
      fields = builtins.filter (field: field != "") (lib.splitString " " cleaned);
      algorithm = if fields == [ ] then "" else builtins.head fields;
      material = if builtins.length fields < 2 then "" else builtins.elemAt fields 1;
    in
    !(lib.hasInfix "\n" cleaned || lib.hasInfix "\r" cleaned)
    && builtins.elem algorithm [
      "ecdsa-sha2-nistp256"
      "ecdsa-sha2-nistp384"
      "ecdsa-sha2-nistp521"
      "sk-ecdsa-sha2-nistp256@openssh.com"
      "sk-ssh-ed25519@openssh.com"
      "ssh-ed25519"
      "ssh-rsa"
    ]
    && builtins.match "[A-Za-z0-9+/=]+" material != null;
in
{
  options.services.nixSecrets.forwarder = {
    enable = lib.mkEnableOption "restricted SSH-to-deployer socket forwarder";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../packages/default.nix { };
      defaultText = lib.literalExpression "the bundled nix-secrets package";
    };
    user = lib.mkOption {
      type = lib.types.str;
      default = "nix-secrets-forward";
    };
    authorizedKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "SSH keys allowed to open only the fixed deployment relay.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = receiver.enable;
        message = "the deployment forwarder requires services.nixSecrets.receiver";
      }
      {
        assertion = config.services.openssh.enable;
        message = "the deployment forwarder requires services.openssh";
      }
      {
        assertion = cfg.authorizedKeys != [ ];
        message = "the deployment forwarder requires at least one authorized key";
      }
      {
        assertion = builtins.all validKey cfg.authorizedKeys;
        message = "deployment forwarder authorized keys must be plain SSH public keys";
      }
    ];

    environment.shells = [ "${cfg.package}/bin/nix-secrets-forward-receiver" ];
    users.groups.${cfg.user} = { };
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.user;
      extraGroups = [ receiver.accessGroup ];
      shell = "${cfg.package}/bin/nix-secrets-forward-receiver";
      # This invalid hash keeps password login impossible while leaving the
      # account usable for its restricted public-key command.
      hashedPassword = "*";
      openssh.authorizedKeys.keys = map forcedKey cfg.authorizedKeys;
    };
  };
}
