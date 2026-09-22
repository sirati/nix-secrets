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
  normalize = generation: secretsLib.normalizeService [ key ] "backup" {
    secrets.passphrase = { inherit destination generation; };
  };
  valid = (normalize secretsLib.generators.backup).passphrase.generation;
  password = (normalize {
    type = "random-password";
    length = 32;
    alphabet = "ascii-safe";
  }).passphrase.generation;
  passphrase = (normalize {
    type = "random-passphrase";
    words = 8;
    separator = "hyphen";
    wordList = "eff-large";
  }).passphrase.generation;
  fails = generation: !(builtins.tryEval (
    builtins.deepSeq (normalize generation) true
  )).success;
in
assert valid == {
  type = "random-bytes";
  bytes = 32;
  encoding = "base64url-unpadded";
};
assert password.length == 32;
assert passphrase.words == 8;
assert fails { type = "random-bytes"; bytes = 15; encoding = "hex"; };
assert fails { type = "random-password"; length = 32; alphabet = "unicode"; };
assert fails {
  type = "random-passphrase";
  words = 8;
  separator = "hyphen";
  wordList = "eff-large";
  unknown = true;
};
true
