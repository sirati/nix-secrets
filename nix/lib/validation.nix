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
    else if destination ? contentType && destination.contentType != "named-ssh-ed25519-public-keys" then
      throw "unsupported secret content type"
    else if
      destination ? contentType
      && (
        !(destination ? authorizedForUser)
        || builtins.match "[A-Za-z0-9_-]{1,32}" destination.authorizedForUser == null
      )
    then
      throw "SSH key inventory requires authorizedForUser"
    else if destination ? authorizedForUser && !(destination ? contentType) then
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
        "hostPublicKeys"
      ];
      bootstrapMissing = builtins.filter (name: !(builtins.hasAttr name bootstrap)) bootstrapRequired;
      bootstrapExtra = builtins.filter (name: !(builtins.elem name bootstrapRequired)) (
        attrNames bootstrap
      );
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
      generated.type == "storage-box-ssh-key" && (keys == [ ] || !(builtins.all validSshPublicKey keys))
    then
      throw "storage-box bootstrap hostPublicKeys must contain complete OpenSSH public key lines"
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
    validSshPublicKey
    validateConsumerConstraints
    validateGeneratedSecret
    ;
}
