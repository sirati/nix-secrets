{ secretsLib }:

let
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  service = port: hostPublicKeys: {
    secrets.storage-key = {
      generation = secretsLib.generators.backup;
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
    builtins.deepSeq (normalize (service 23 [ key key ])) true
  );
in
assert generated.kind == "generated";
assert generated.generatedSecret.type == "storage-box-ssh-key";
assert generated.generatedSecret.bootstrap.port == 23;
assert generated.generation == secretsLib.generators.backup;
assert !invalidPort.success;
assert !duplicatePins.success;
true
