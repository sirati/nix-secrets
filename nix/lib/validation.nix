{ lib }:
let
  inherit (builtins) attrNames isAttrs;

  validateDestination =
    serviceName: destination:
    let
      required = [
        "path"
        "owner"
        "group"
        "mode"
        "category"
      ];
      missing = builtins.filter (name: !(builtins.hasAttr name destination)) required;
      extra = builtins.filter (
        name:
        !(builtins.elem name (
          required
          ++ [
            "contentType"
            "authorizedForUser"
          ]
        ))
      ) (attrNames destination);
      parts = lib.splitString "/" destination.path;
      validCategory = builtins.elem destination.category [
        "setup"
        "service"
        "backup"
      ];
      validPath =
        builtins.length parts == 6
        && builtins.elemAt parts 0 == ""
        && builtins.elemAt parts 1 == "persistent"
        && builtins.elemAt parts 2 == "secrets"
        && builtins.elemAt parts 3 == serviceName
        && builtins.elemAt parts 4 == destination.category
        && builtins.elemAt parts 5 != "";
    in
    if missing != [ ] then
      throw "secret destination is missing: ${lib.concatStringsSep ", " missing}"
    else if extra != [ ] then
      throw "secret destination has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if
      destination ? contentType
      && !(builtins.elem destination.contentType [
        "named-ssh-ed25519-public-keys"
        "openssh-private-key"
        "openssh-public-key"
      ])
    then
      throw "unsupported secret content type"
    else if
      (destination.contentType or null) == "named-ssh-ed25519-public-keys"
      && (
        !(destination ? authorizedForUser)
        || builtins.match "[A-Za-z0-9_-]{1,32}" destination.authorizedForUser == null
      )
    then
      throw "SSH key inventory requires authorizedForUser"
    else if
      destination ? authorizedForUser
      && (destination.contentType or null) != "named-ssh-ed25519-public-keys"
    then
      throw "authorizedForUser requires a content type"
    else if !validCategory then
      throw "secret category must be setup, service, or backup"
    else if !validPath then
      throw "secret destination ${destination.path} has an invalid persistent-secret layout"
    else if destination.owner == "" || destination.group == "" then
      throw "secret destination owner and group must not be empty"
    else if
      !(builtins.elem destination.mode [
        "0400"
        "0440"
      ])
    then
      throw "secret destination mode must be 0400 or 0440"
    else
      destination;

  validatePublicDestination =
    sharedId: destination:
    let
      expected = "/persistent/public-info/${sharedId}";
      parts = lib.splitString "/" sharedId;
      validPart = part: builtins.match "[A-Za-z0-9_-]+" part != null && part != "." && part != "..";
    in
    if builtins.length parts != 2 || !(builtins.all validPart parts) then
      throw "public-info sharedPublicId has invalid path components"
    else if destination.path != expected || destination.category != "public-info" then
      throw "public-info destination must be ${expected} with category public-info"
    else if
      destination.owner != "root" || destination.group != "root" || destination.mode != "0644"
    then
      throw "public-info destination must be root:root 0644"
    else if (destination.contentType or null) != "ssh-known-hosts" then
      throw "public-info currently requires contentType=ssh-known-hosts"
    else if
      builtins.attrNames destination != [
        "category"
        "contentType"
        "group"
        "mode"
        "owner"
        "path"
      ]
    then
      throw "public-info destination has unknown fields"
    else
      destination;

  validSshPublicKey =
    key:
    !(lib.hasInfix "\n" key)
    && !(lib.hasInfix "\r" key)
    &&
      builtins.match "(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))[[:space:]]+[A-Za-z0-9+/]+={0,2}([[:space:]]+[^[:space:]].*)?" key
      != null;

  validateConsumerConstraints =
    constraints:
    let
      allowed = [
        "cannotHandleShorterThan"
        "cannotHandleLongerThan"
        "matchingRegex"
      ];
      extra = builtins.filter (name: !(builtins.elem name allowed)) (attrNames constraints);
      minimum = constraints.cannotHandleShorterThan or 0;
      maximum = constraints.cannotHandleLongerThan or minimum;
    in
    if !isAttrs constraints then
      throw "consumerConstraints must be an attribute set"
    else if extra != [ ] then
      throw "consumerConstraints has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if
      !(
        builtins.isInt minimum
        && minimum >= 0
        && builtins.isInt maximum
        && maximum >= 0
        && minimum <= maximum
      )
    then
      throw "consumerConstraints has invalid length bounds"
    else if
      constraints ? matchingRegex
      && (
        !builtins.isString constraints.matchingRegex
        || constraints.matchingRegex == ""
        || builtins.stringLength constraints.matchingRegex > 4096
      )
    then
      throw "consumerConstraints.matchingRegex must contain 1 through 4096 characters"
    else
      constraints;

  # Byte-exact format of a value the target generates when it is unset:
  # prefix + encode(random bytes) + suffix. See README "Generated at deployment".
  validateValueGenerator =
    generator:
    let
      allowed = [
        "kind"
        "bytes"
        "encoding"
        "prefix"
        "suffix"
      ];
      extra = builtins.filter (name: !(builtins.elem name allowed)) (attrNames generator);
      affixOk =
        name:
        !(generator ? ${name})
        || (builtins.isString generator.${name} && builtins.stringLength generator.${name} <= 1024);
    in
    if !isAttrs generator then
      throw "valueGenerator must be an attribute set"
    else if extra != [ ] then
      throw "valueGenerator has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if (generator.kind or null) != "random-bytes" then
      throw "valueGenerator.kind must be \"random-bytes\""
    else if
      !(builtins.isInt (generator.bytes or null) && generator.bytes >= 16 && generator.bytes <= 1024)
    then
      throw "valueGenerator.bytes must be an integer from 16 through 1024"
    else if
      !(builtins.elem (generator.encoding or null) [
        "base64"
        "base64url"
        "hex"
      ])
    then
      throw "valueGenerator.encoding must be base64, base64url, or hex"
    else if !(affixOk "prefix" && affixOk "suffix") then
      throw "valueGenerator prefix and suffix must be strings of at most 1024 bytes"
    else
      generator;

  # A command run on the operator's machine: nix run <installable> -- <args>.
  # It writes the private key to stdout and the public key to fd 3.
  validateKeypairGenerator =
    generator:
    let
      extra = builtins.filter (name: !(builtins.elem name [ "installable" "args" ])) (attrNames generator);
      args = generator.args or [ ];
    in
    if !isAttrs generator then
      throw "generator must be an attribute set"
    else if extra != [ ] then
      throw "generator has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if
      !(builtins.isString (generator.installable or null))
      || generator.installable == ""
      || lib.hasPrefix "-" generator.installable
    then
      throw "generator.installable must be a flake installable"
    else if !(builtins.isList args && builtins.all builtins.isString args && builtins.length args <= 64) then
      throw "generator.args must be a list of at most 64 strings"
    else
      generator // { inherit args; };

  # Deployed as prefix + <value of identifier> + suffix; never stored itself.
  validateDerivedFrom =
    derived:
    let
      extra = builtins.filter (name: !(builtins.elem name [ "identifier" "prefix" "suffix" ])) (
        attrNames derived
      );
      affixOk =
        name:
        !(derived ? ${name})
        || (builtins.isString derived.${name} && builtins.stringLength derived.${name} <= 1024);
    in
    if !isAttrs derived then
      throw "derivedFrom must be an attribute set"
    else if extra != [ ] then
      throw "derivedFrom has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if
      !(builtins.isString (derived.identifier or null))
      || builtins.match "[A-Za-z0-9_-]+\\.(services|user-[A-Za-z0-9_-]+-services)(\\.[A-Za-z0-9_-]+){2,}" derived.identifier == null
    then
      throw "derivedFrom.identifier must be a canonical secret identifier"
    else if !(affixOk "prefix" && affixOk "suffix") then
      throw "derivedFrom prefix and suffix must be strings of at most 1024 bytes"
    else
      derived;

  validateGeneratedSecret =
    serviceName: generated:
    let
      required = [
        "type"
        "output"
      ];
      missing = builtins.filter (name: !(builtins.hasAttr name generated)) required;
      extra = builtins.filter (
        name:
        !(builtins.elem name (
          required
          ++ [
            "bootstrap"
            "registerAt"
          ]
        ))
      ) (attrNames generated);
      bootstrap = generated.bootstrap or { };
      bootstrapRequired = [
        "host"
        "port"
        "user"
      ];
      bootstrapMissing = builtins.filter (name: !(builtins.hasAttr name bootstrap)) bootstrapRequired;
      bootstrapExtra = builtins.filter (
        name:
        !(builtins.elem name (
          bootstrapRequired
          ++ [
            "hostPublicKeys"
            "knownHostsFile"
          ]
        ))
      ) (attrNames bootstrap);
      keys = bootstrap.hostPublicKeys or [ ];
    in
    if missing != [ ] then
      throw "generated secret is missing: ${lib.concatStringsSep ", " missing}"
    else if extra != [ ] then
      throw "generated secret has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if
      !(builtins.elem generated.type [
        "storage-box-ssh-key"
        "local-ssh-key"
      ])
    then
      throw "unsupported generated secret type ${generated.type}"
    else if
      generated.type == "local-ssh-key"
      && (generated ? bootstrap || generated.output.category != "service")
    then
      throw "local SSH key requires a service output and no bootstrap"
    else if generated.type == "storage-box-ssh-key" && generated ? registerAt then
      throw "storage-box key cannot register another secret"
    else if generated.type == "storage-box-ssh-key" && bootstrapMissing != [ ] then
      throw "storage-box bootstrap is missing: ${lib.concatStringsSep ", " bootstrapMissing}"
    else if generated.type == "storage-box-ssh-key" && bootstrapExtra != [ ] then
      throw "storage-box bootstrap has unknown fields: ${lib.concatStringsSep ", " bootstrapExtra}"
    else if
      generated.type == "storage-box-ssh-key" && (bootstrap.host == "" || bootstrap.user == "")
    then
      throw "storage-box bootstrap host and user must not be empty"
    else if generated.type == "storage-box-ssh-key" && bootstrap.port != 23 then
      throw "storage-box bootstrap port must be 23"
    else if
      generated.type == "storage-box-ssh-key"
      && ((keys == [ ]) == !(bootstrap ? knownHostsFile) || !(builtins.all validSshPublicKey keys))
    then
      throw "storage-box bootstrap requires either hostPublicKeys or knownHostsFile"
    else if
      generated.type == "storage-box-ssh-key"
      && bootstrap ? knownHostsFile
      && (
        builtins.match "/persistent/public-info/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)+" bootstrap.knownHostsFile
        == null
      )
    then
      throw "storage-box bootstrap knownHostsFile must be a persistent public-info path"
    else if
      generated.type == "storage-box-ssh-key" && builtins.length keys != builtins.length (lib.unique keys)
    then
      throw "storage-box bootstrap hostPublicKeys must not contain duplicates"
    else
      generated // { output = validateDestination serviceName generated.output; };

in
{
  inherit
    validateDestination
    validatePublicDestination
    validSshPublicKey
    validateConsumerConstraints
    validateGeneratedSecret
    validateValueGenerator
    validateKeypairGenerator
    validateDerivedFrom
    ;
}
