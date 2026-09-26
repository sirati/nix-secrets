{ secretsLib, lib }:
let
  key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f pin";
  generator = {
    installable = "github:example/tool#keygen";
    args = [ ];
  };
  token = {
    requiredForInstall = true;
    destination = {
      path = "/persistent/secrets/nmbl/service/token";
      category = "service";
      owner = "root";
      group = "root";
      mode = "0400";
    };
  };
  host = secretsLib.normalizeHost {
    hostName = "host";
    socketPath = "/run/s";
    deployment = {
      host = "host";
      destination = "secrets@host";
      port = 22;
    };
    defaultRecipientPublicKeys = [ key ];
    services.nmbl.secrets = {
      generation-key = {
        kind = "operator";
        requiredForInstall = true;
        inherit generator;
      };
      manual = {
        kind = "operator";
        requiredForInstall = true;
      };
      optional = {
        kind = "operator";
        inherit generator;
      };
      inherit token;
    };
  };
  required = secretsLib.requiredForInstallLeaves host;
  ids = map (entry: entry.identifier) required;
  empty = builtins.toFile "empty.toml" "";
  # generation-key has a record but no public key yet; manual has a record.
  partial = builtins.toFile "partial.toml" ''
    [secrets."host.services.nmbl.generation-key"]
    age_ciphertext = "YWdl"
    [secrets."host.services.nmbl.manual"]
    age_ciphertext = "YWdl"
  '';
  full = builtins.toFile "full.toml" ''
    [secrets."host.services.nmbl.generation-key"]
    age_ciphertext = "YWdl"
    public_key = "AQJwdWJsaWM="
    [secrets."host.services.nmbl.manual"]
    age_ciphertext = "YWdl"
    [secrets."host.services.nmbl.token"]
    age_ciphertext = "YWdl"
  '';
  fails = expression: !(builtins.tryEval (builtins.deepSeq expression true)).success;
  service = secrets: secretsLib.normalizeService [ key ] "nmbl" { inherit secrets; };
  message = secretsLib.missingBeforeInstallMessage "host.services.nmbl.token";
in
assert lib.sort lib.lessThan ids == [
  "host.services.nmbl.generation-key"
  "host.services.nmbl.manual"
  "host.services.nmbl.token"
];
assert secretsLib.missingBeforeInstall empty required == ids;
assert secretsLib.missingBeforeInstall /nonexistent/store.toml required == ids;
assert secretsLib.missingBeforeInstall partial required == [
  "host.services.nmbl.generation-key"
  "host.services.nmbl.token"
];
assert secretsLib.missingBeforeInstall full required == [ ];
# An identifier from elsewhere, without its leaf, needs any record.
assert secretsLib.missingBeforeInstall partial [ { identifier = "other.services.x.y"; leaf = null; } ] == [
  "other.services.x.y"
];
assert lib.hasPrefix "generate/enter host.services.nmbl.token in the nix-secrets TUI first" message;
assert secretsLib.requireOperatorPublicKey full "host.services.nmbl.generation-key" == "AQJwdWJsaWM=";
assert fails (secretsLib.requireOperatorPublicKey partial "host.services.nmbl.generation-key");
assert fails (service { bad = token // { requiredForInstall = "yes"; }; });
assert fails (
  service {
    bad = token // {
      derivedFrom.identifier = "host.services.nmbl.manual";
    };
  }
);
true
