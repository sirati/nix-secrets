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
          contentType = "openssh-private-key";
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
      externalInputRequired = true;
      identity = {
        service = "mail";
        responsibility = "backup";
        namespace = "shared";
        name = "storage-key";
      };
    };
  }).host.services.backup.storage-key;
  publicLeaf = extra: {
    kind = "public-info";
    sharedPublicId = "storage-box/known-hosts";
    expectedSshHost = "u123.storagebox.example";
    expectedSshPort = 23;
    installDefaultIfMissing = true;
    destination = {
      path = "/persistent/public-info/storage-box/known-hosts";
      category = "public-info";
      owner = "root";
      group = "root";
      mode = "0644";
      contentType = "ssh-known-hosts";
    };
  } // extra;
  publicOf = extra: (normalize { secrets.known-hosts = publicLeaf extra; }).known-hosts;
  withDefault = publicOf {
    expectedSshHosts = [ "u123-sub1.storagebox.example" ];
    defaultValue = "[u123-sub1.storagebox.example]:23 ssh-ed25519 AAAA
";
  };
  badHosts = builtins.tryEval (builtins.deepSeq (publicOf { expectedSshHosts = "one"; }) true);
  badDefault = builtins.tryEval (builtins.deepSeq (publicOf { defaultValue = ""; }) true);
in
assert withDefault.expectedSshHosts == [ "u123-sub1.storagebox.example" ];
assert withDefault.defaultValue != "";
assert !badHosts.success;
assert !badDefault.success;
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
assert semantic.presentation.facing == "external";
true
