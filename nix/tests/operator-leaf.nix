{ secretsLib }:
let
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  service = secrets: secretsLib.normalizeService [ key ] "signing" { inherit secrets; };
  generator = {
    installable = "github:sirati/siratis-nmbl-bootloader?dir=sirati-nmbl/nmbl-init-rs#nmbl-sign";
    args = [ "keygen" "--alg" "ml-dsa-65" "--stdio" ];
  };
  normalized = service {
    generation-key = {
      kind = "operator";
      inherit generator;
    };
    manual = {
      kind = "operator";
    };
    token.destination = {
      path = "/persistent/secrets/signing/service/token";
      category = "service";
      owner = "root";
      group = "root";
      mode = "0400";
    };
  };
  fails = secrets: !(builtins.tryEval (builtins.deepSeq (service secrets) true)).success;
  hostTree = secretsLib.withoutOperatorLeaves normalized;
  store = builtins.toFile "store.toml" ''
    [secrets."host.services.signing.generation-key"]
    format_version = 1
    version_id = "AAAAAAAAAAAAAAAAAAAAAA=="
    recipient_ids = ["x"]
    age_ciphertext = "YWdl"
    public_key = "AQJwdWJsaWM="
  '';
in
assert normalized.generation-key.kind == "operator";
assert normalized.generation-key.generator == generator;
assert normalized.generation-key.recipientIds != [ ];
assert !(normalized.manual ? generator);
assert !(normalized.generation-key ? destination);
# Operator leaves never reach a host manifest or a readiness waiter.
assert builtins.attrNames hostTree == [ "token" ];
assert builtins.length (builtins.filter secretsLib.isOperatorLeaf (secretsLib.collectLeaves normalized)) == 2;
assert fails { bad = { kind = "operator"; destination = normalized.token.destination; }; };
assert fails { bad = { kind = "operator"; generator = { installable = "-x"; }; }; };
assert fails { bad = { kind = "operator"; generator = generator // { extra = 1; }; }; };
assert fails { bad = { kind = "operator"; valueType = "key"; }; };
assert secretsLib.operatorPublicKey store "host.services.signing.generation-key" == "AQJwdWJsaWM=";
assert secretsLib.operatorPublicKey store "host.services.signing.other" == null;
assert secretsLib.operatorPublicKey /nonexistent/store.toml "x" == null;
true
