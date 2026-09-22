{ pkgs, module, hostKey, wrongHostKey, unrelatedKey }:

{ config, ... }:

let
  publicKey = path:
    pkgs.lib.removeSuffix "\n" (builtins.readFile "${path}/id.pub");
  output = name: {
    path = "/persistent/secrets/backup/backup/${name}";
    category = "backup";
    owner = "backup";
    group = "backup";
    mode = "0400";
  };
  bootstrap = key: {
    host = "127.0.0.1";
    port = 23;
    user = "storagebox";
    hostPublicKeys = [ (publicKey key) ];
  };
in
{
  imports = [ module ];

  environment.systemPackages = [
    pkgs.openssh
    pkgs.python3
    config.services.nixSecrets.receiver.package
  ];

  users.groups.backup = { };
  users.users.backup = {
    isSystemUser = true;
    group = "backup";
  };
  users.users.storagebox = {
    isNormalUser = true;
    home = "/var/lib/storagebox";
    createHome = true;
    initialPassword = "bootstrap-password";
  };

  services.openssh = {
    enable = true;
    ports = [ 23 ];
    hostKeys = [{
      path = "/persistent/storagebox-host-key";
      type = "ed25519";
    }];
    settings = {
      PasswordAuthentication = true;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "no";
    };
  };

  systemd.tmpfiles.rules = [
    "d /persistent 0755 root root - -"
    "C /persistent/storagebox-host-key 0600 root root - ${hostKey}/id"
  ];

  services.nixSecrets = {
    enable = true;
    defaultRecipientPublicKeys = [ (publicKey unrelatedKey) ];
    receiver.enable = true;
    services.backup.secrets = {
      storageBoxKey.generatedSecret = {
        type = "storage-box-ssh-key";
        output = output "storage-box-key";
        bootstrap = bootstrap hostKey;
      };
      rejectedKey.generatedSecret = {
        type = "storage-box-ssh-key";
        output = output "rejected-key";
        bootstrap = bootstrap wrongHostKey;
      };
    };
  };

  system.stateVersion = "26.05";
}
