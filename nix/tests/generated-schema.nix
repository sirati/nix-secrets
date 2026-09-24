{ secretsLib }:

let
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  service = port: hostPublicKeys: {
    secrets.storage-key = {
      valueType = "password";
      generatedSecret = {
        type = "storage-box-ssh-key";
        output = {
          path = "/persistent/secrets/backup/backup/storage-key";
          category = "backup";
          owner = "backup";
          group = "backup";
          mode = "0400";
        };
        bootstrap = {
          host = "u123.storagebox.example";
          inherit port hostPublicKeys;
          user = "u123";
        };
      };
    };
  };
  normalize = value: secretsLib.normalizeService [ key ] "backup" value;
  generated = (normalize (service 23 [ key ])).storage-key;
  invalidPort = builtins.tryEval (builtins.deepSeq (normalize (service 22 [ key ])) true);
  duplicatePins = builtins.tryEval (
    builtins.deepSeq (normalize (
      service 23 [
        key
        key
      ]
    )) true
  );
  semantic = (secretsLib.normalizeHost {
    hostName = "host";
    socketPath = "/run/nix-secrets/backend.sock";
    deployment = { host = "host"; destination = "secrets@host"; port = 22; };
    defaultRecipientPublicKeys = [ key ];
    services.backup.secrets.storage-key = (service 23 [ key ]).secrets.storage-key // {
      identity = {
        service = "mail";
        responsibility = "backup";
        namespace = "shared";
        name = "storage-key";
      };
    };
  }).host.services.backup.storage-key;
in
assert generated.kind == "generated";
assert generated.generatedSecret.type == "storage-box-ssh-key";
assert generated.generatedSecret.bootstrap.port == 23;
assert generated.valueType == "password";
assert !invalidPort.success;
assert !duplicatePins.success;
assert semantic.identity.host == "host";
assert semantic.identity.scope == "system";
assert semantic.identity.user == null;
assert semantic.identity.service == "mail";
assert semantic.identity.namespace == "shared";
assert semantic.presentation.type == "passphrase";
true
