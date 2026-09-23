{ lib }:

let
  inherit (builtins) attrNames concatLists hashString isAttrs mapAttrs;

  recipientId = publicKey:
    let
      fields = builtins.filter (field: field != "") (lib.splitString " " publicKey);
      canonical = lib.concatStringsSep " " (lib.take 2 fields);
    in
    if builtins.length fields < 2 then
      throw "recipient public key is not an SSH public key"
    else
      hashString "sha256" canonical;

  validateDestination = serviceName: destination:
    let
      required = [ "path" "owner" "group" "mode" "category" ];
      missing = builtins.filter (name: !(builtins.hasAttr name destination)) required;
      extra = builtins.filter (name: !(builtins.elem name (required ++ [ "contentType" "authorizedForUser" ]))) (attrNames destination);
      parts = lib.splitString "/" destination.path;
      validCategory = builtins.elem destination.category [ "setup" "service" "backup" ];
      validPath = builtins.length parts == 6
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
    else if destination ? contentType && (!(destination ? authorizedForUser) || builtins.match "[A-Za-z0-9_-]{1,32}" destination.authorizedForUser == null) then
      throw "SSH key inventory requires authorizedForUser"
    else if destination ? authorizedForUser && !(destination ? contentType) then
      throw "authorizedForUser requires a content type"
    else if !validCategory then
      throw "secret category must be setup, service, or backup"
    else if !validPath then
      throw "secret destination ${destination.path} has an invalid persistent-secret layout"
    else if destination.owner == "" || destination.group == "" then
      throw "secret destination owner and group must not be empty"
    else if !(builtins.elem destination.mode [ "0400" "0440" ]) then
      throw "secret destination mode must be 0400 or 0440"
    else
      destination;

  validSshPublicKey = key:
    !(lib.hasInfix "\n" key) && !(lib.hasInfix "\r" key)
    && builtins.match ''(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))[[:space:]]+[A-Za-z0-9+/]+={0,2}([[:space:]]+[^[:space:]].*)?'' key != null;

  validateGeneration = generation:
    let
      type = generation.type or null;
      specs = {
        random-password = {
          fields = [ "type" "length" "alphabet" ];
          valid = generation ? length && generation ? alphabet
            && builtins.isInt generation.length
            && generation.length >= 16 && generation.length <= 256
            && builtins.elem generation.alphabet [ "alphanumeric" "ascii-safe" ];
        };
        random-passphrase = {
          fields = [ "type" "words" "separator" "wordList" ];
          valid = generation ? words && generation ? separator && generation ? wordList
            && builtins.isInt generation.words
            && generation.words >= 6 && generation.words <= 24
            && builtins.elem generation.separator [ "hyphen" "underscore" "space" ]
            && generation.wordList == "eff-large";
        };
        random-bytes = {
          fields = [ "type" "bytes" "encoding" ];
          valid = generation ? bytes && generation ? encoding
            && builtins.isInt generation.bytes
            && generation.bytes >= 16 && generation.bytes <= 4096
            && builtins.elem generation.encoding [ "base64url-unpadded" "base64" "hex" ];
        };
      };
      spec = specs.${toString type} or null;
      extra = if spec == null then [ ] else
        builtins.filter (name: !(builtins.elem name spec.fields)) (attrNames generation);
    in
    if !isAttrs generation then
      throw "secret generation policy must be an attribute set"
    else if spec == null then
      throw "unsupported secret generation policy ${toString type}"
    else if extra != [ ] then
      throw "secret generation policy has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if !spec.valid then
      throw "secret generation policy ${type} has invalid or missing parameters"
    else
      generation;

  validateGeneratedSecret = serviceName: generated:
    let
      required = [ "type" "output" ];
      missing = builtins.filter (name: !(builtins.hasAttr name generated)) required;
      extra = builtins.filter (name: !(builtins.elem name (required ++ [ "bootstrap" "registerAt" ]))) (attrNames generated);
      bootstrap = generated.bootstrap or { };
      bootstrapRequired = [ "host" "port" "user" "hostPublicKeys" ];
      bootstrapMissing = builtins.filter (name: !(builtins.hasAttr name bootstrap)) bootstrapRequired;
      bootstrapExtra = builtins.filter (
        name: !(builtins.elem name bootstrapRequired)
      ) (attrNames bootstrap);
      keys = bootstrap.hostPublicKeys or [ ];
    in
    if missing != [ ] then
      throw "generated secret is missing: ${lib.concatStringsSep ", " missing}"
    else if extra != [ ] then
      throw "generated secret has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if !(builtins.elem generated.type [ "storage-box-ssh-key" "local-ssh-key" ]) then
      throw "unsupported generated secret type ${generated.type}"
    else if generated.type == "local-ssh-key" && (generated ? bootstrap || generated.output.category != "service") then
      throw "local SSH key requires a service output and no bootstrap"
    else if generated.type == "storage-box-ssh-key" && generated ? registerAt then
      throw "storage-box key cannot register another secret"
    else if generated.type == "storage-box-ssh-key" && bootstrapMissing != [ ] then
      throw "storage-box bootstrap is missing: ${lib.concatStringsSep ", " bootstrapMissing}"
    else if generated.type == "storage-box-ssh-key" && bootstrapExtra != [ ] then
      throw "storage-box bootstrap has unknown fields: ${lib.concatStringsSep ", " bootstrapExtra}"
    else if generated.type == "storage-box-ssh-key" && (bootstrap.host == "" || bootstrap.user == "") then
      throw "storage-box bootstrap host and user must not be empty"
    else if generated.type == "storage-box-ssh-key" && bootstrap.port != 23 then
      throw "storage-box bootstrap port must be 23"
    else if generated.type == "storage-box-ssh-key" && (keys == [ ] || !(builtins.all validSshPublicKey keys)) then
      throw "storage-box bootstrap hostPublicKeys must contain complete OpenSSH public key lines"
    else if generated.type == "storage-box-ssh-key" && builtins.length keys != builtins.length (lib.unique keys) then
      throw "storage-box bootstrap hostPublicKeys must not contain duplicates"
    else
      generated // { output = validateDestination serviceName generated.output; };

  normalizeLeaf = context: node:
    let
      keys = node.recipientPublicKeys or context.recipientPublicKeys;
      allowed = [ "destination" "recipientPublicKeys" "consumerUnits" "generation" ];
      extra = builtins.filter (name: !(builtins.elem name allowed)) (attrNames node);
    in
    if extra != [ ] then
      throw "secret leaf has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if keys == [ ] then
      throw "secret ${node.destination.path} has no recipient public key"
    else
      builtins.removeAttrs node [ "recipientPublicKeys" ] // {
        kind = "secret";
        recipientPublicKeys = keys;
        recipientIds = map recipientId keys;
        destination = validateDestination context.serviceName node.destination;
        consumerUnits = node.consumerUnits or context.consumerUnits;
      } // lib.optionalAttrs (node ? generation) {
        generation = validateGeneration node.generation;
      };

  normalizeGeneratedLeaf = context: node:
    let
      keys = node.recipientPublicKeys or context.recipientPublicKeys;
      generated = validateGeneratedSecret context.serviceName node.generatedSecret;
      allowed = [ "generatedSecret" "recipientPublicKeys" "consumerUnits" "generation" ];
      extra = builtins.filter (name: !(builtins.elem name allowed)) (attrNames node);
    in
    if extra != [ ] then
      throw "generated secret leaf has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if keys == [ ] || !(builtins.all validSshPublicKey keys) then
      throw "generated secret ${generated.output.path} has no valid recipient public key"
    else
      builtins.removeAttrs node [ "recipientPublicKeys" ] // {
        kind = "generated";
        recipientPublicKeys = keys;
        recipientIds = map recipientId keys;
        generatedSecret = generated;
        consumerUnits = node.consumerUnits or context.consumerUnits;
      } // lib.optionalAttrs (node ? generation) {
        generation = validateGeneration node.generation;
      };

  normalizeTree = context: tree:
    let
      inheritedKeys = tree._recipientPublicKeys or context.recipientPublicKeys;
      childContext = context // { recipientPublicKeys = inheritedKeys; };
      names = builtins.filter (name: name != "_recipientPublicKeys") (attrNames tree);
    in
    lib.genAttrs names (
      name:
      let
        node = tree.${name};
      in
      if !isAttrs node then
        throw "secret tree entry ${name} must be an attribute set"
      else if node ? destination && node ? generatedSecret then
        throw "secret tree entry ${name} cannot have destination and generatedSecret"
      else if node ? destination then
        normalizeLeaf childContext node
      else if node ? generatedSecret then
        normalizeGeneratedLeaf childContext node
      else
        normalizeTree childContext node
    );

  collectLeaves = tree:
    concatLists (
      map (
        name:
        let node = tree.${name};
        in if node ? destination || node ? generatedSecret then [ node ] else collectLeaves node
      ) (attrNames tree)
    );

  normalizeService = defaultKeys: serviceName: service:
    normalizeTree {
      inherit serviceName;
      recipientPublicKeys = service.recipientPublicKeys or defaultKeys;
      consumerUnits = service.consumerUnits or [ ];
    } service.secrets;

  normalizeServices = defaultKeys: services:
    mapAttrs (normalizeService defaultKeys) services;

  normalizeHost = {
    hostName,
    socketPath,
    deployment,
    defaultRecipientPublicKeys ? [ ],
    services ? { },
    userServices ? { },
  }:
    let
      system = normalizeServices defaultRecipientPublicKeys services;
      users = mapAttrs (_: normalizeServices defaultRecipientPublicKeys) userServices;
    in
    {
      ${hostName} = {
        metadata = { inherit socketPath deployment; };
        services = system;
      } // lib.mapAttrs' (
        user: value: lib.nameValuePair "user-${user}-services" value
      ) users;
    };
in
{
  generators.backup = {
    type = "random-bytes";
    bytes = 32;
    encoding = "base64url-unpadded";
  };
  inherit collectLeaves normalizeHost normalizeService normalizeServices recipientId
    validSshPublicKey validateGeneration;
}
