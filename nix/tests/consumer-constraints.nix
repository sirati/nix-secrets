{ secretsLib }:
let
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  destination = {
    path = "/persistent/secrets/backup/backup/passphrase";
    category = "backup";
    owner = "backup";
    group = "backup";
    mode = "0400";
  };
  normalize =
    leaf:
    secretsLib.normalizeService [ key ] "backup" {
      secrets.passphrase = leaf // {
        inherit destination;
      };
    };
  constraints = {
    cannotHandleShorterThan = 8;
    cannotHandleLongerThan = 64;
    matchingRegex = "[A-Za-z0-9]+";
  };
  valid =
    (normalize {
      valueType = "password";
      consumerConstraints = constraints;
    }).passphrase;
  fails = leaf: !(builtins.tryEval (builtins.deepSeq (normalize leaf) true)).success;
in
assert valid.valueType == "password";
assert valid.consumerConstraints == constraints;
assert fails { consumerConstraints = constraints; };
assert fails {
  valueType = "password";
  consumerConstraints.cannotHandleShorterThan = 65;
  consumerConstraints.cannotHandleLongerThan = 64;
};
assert fails {
  valueType = "password";
  consumerConstraints.matchingRegex = "";
};
assert fails {
  valueType = "password";
  generation.type = "random-password";
};
true
