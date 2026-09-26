{ secretsLib }:
let
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  normalize =
    leaf:
    (secretsLib.normalizeService [ key ] "app" {
      secrets.value = {
        destination = {
          path = "/persistent/secrets/app/service/value";
          category = "service";
          owner = "root";
          group = "root";
          mode = "0400";
        };
      } // leaf;
    }).value;
  fails = leaf: !(builtins.tryEval (builtins.deepSeq (normalize leaf) true)).success;
  tsig = {
    kind = "random-bytes";
    bytes = 32;
    encoding = "base64";
    prefix = "key:\n  - id: dns-transfer\n    algorithm: hmac-sha256\n    secret: ";
    suffix = "\n";
  };
in
assert (normalize { valueType = "key"; valueGenerator = tsig; }).valueGenerator == tsig;
assert (normalize { valueType = "password"; generateOnDeploy = false; }).generateOnDeploy == false;
assert fails { valueType = "key"; valueGenerator = tsig // { bytes = 8; }; };
assert fails { valueType = "key"; valueGenerator = tsig // { encoding = "base32"; }; };
assert fails { valueType = "key"; valueGenerator = tsig // { kind = "tsig"; }; };
assert fails { valueType = "key"; valueGenerator = tsig // { extra = 1; }; };
assert fails { valueType = "password"; valueGenerator = tsig; };
assert fails { valueType = "key"; externalInputRequired = true; valueGenerator = tsig; };
assert fails { generateOnDeploy = "no"; };
assert
  (normalize {
    valueType = "key";
    derivedFrom = {
      identifier = "server-hetzner2.services.stalwart.dns-update-key";
      prefix = "key:\n  - id: stalwart-dns\n    algorithm: hmac-sha256\n    secret: ";
      suffix = "\n";
    };
  }).derivedFrom.identifier == "server-hetzner2.services.stalwart.dns-update-key";
assert fails { derivedFrom.identifier = "not an identifier"; };
assert fails { derivedFrom = { identifier = "h.services.a.b"; extra = 1; }; };
assert fails { derivedFrom.identifier = "h.services.a.b"; valueGenerator = tsig; valueType = "key"; };
true
