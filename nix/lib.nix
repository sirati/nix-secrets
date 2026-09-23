{ lib }:

let
  inherit (builtins)
    attrNames
    concatLists
    hashString
    isAttrs
    mapAttrs
    ;

  recipientId =
    publicKey:
    let
      fields = builtins.filter (field: field != "") (lib.splitString " " publicKey);
      canonical = lib.concatStringsSep " " (lib.take 2 fields);
    in
    if builtins.length fields < 2 then
      throw "recipient public key is not an SSH public key"
    else
      hashString "sha256" canonical;

  inherit (import ./lib/validation.nix { inherit lib; })
    validateDestination
    validSshPublicKey
    validateConsumerConstraints
    validateGeneratedSecret
    ;

  normalizeLeaf =
    context: node:
    let
      keys = node.recipientPublicKeys or context.recipientPublicKeys;
      allowed = [
        "destination"
        "recipientPublicKeys"
        "consumerUnits"
        "valueType"
        "consumerConstraints"
      ];
      extra = builtins.filter (name: !(builtins.elem name allowed)) (attrNames node);
    in
    if extra != [ ] then
      throw "secret leaf has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if keys == [ ] then
      throw "secret ${node.destination.path} has no recipient public key"
    else if node ? valueType && node.valueType != "password" then
      throw "unsupported secret valueType"
    else if node ? consumerConstraints && (node.valueType or null) != "password" then
      throw "consumerConstraints requires valueType=password"
    else
      builtins.removeAttrs node [ "recipientPublicKeys" ]
      // {
        kind = "secret";
        recipientPublicKeys = keys;
        recipientIds = map recipientId keys;
        destination = validateDestination context.serviceName node.destination;
        consumerUnits = node.consumerUnits or context.consumerUnits;
      }
      // lib.optionalAttrs (node ? consumerConstraints) {
        consumerConstraints = validateConsumerConstraints node.consumerConstraints;
      };

  normalizeGeneratedLeaf =
    context: node:
    let
      keys = node.recipientPublicKeys or context.recipientPublicKeys;
      generated = validateGeneratedSecret context.serviceName node.generatedSecret;
      allowed = [
        "generatedSecret"
        "recipientPublicKeys"
        "consumerUnits"
        "valueType"
        "consumerConstraints"
      ];
      extra = builtins.filter (name: !(builtins.elem name allowed)) (attrNames node);
    in
    if extra != [ ] then
      throw "generated secret leaf has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if keys == [ ] || !(builtins.all validSshPublicKey keys) then
      throw "generated secret ${generated.output.path} has no valid recipient public key"
    else if node ? valueType && node.valueType != "password" then
      throw "unsupported secret valueType"
    else if node ? consumerConstraints && (node.valueType or null) != "password" then
      throw "consumerConstraints requires valueType=password"
    else
      builtins.removeAttrs node [ "recipientPublicKeys" ]
      // {
        kind = "generated";
        recipientPublicKeys = keys;
        recipientIds = map recipientId keys;
        generatedSecret = generated;
        consumerUnits = node.consumerUnits or context.consumerUnits;
      }
      // lib.optionalAttrs (node ? consumerConstraints) {
        consumerConstraints = validateConsumerConstraints node.consumerConstraints;
      };

  normalizeTree =
    context: tree:
    let
      inheritedKeys = tree._recipientPublicKeys or context.recipientPublicKeys;
      childContext = context // {
        recipientPublicKeys = inheritedKeys;
      };
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

  collectLeaves =
    tree:
    concatLists (
      map (
        name:
        let
          node = tree.${name};
        in
        if node ? destination || node ? generatedSecret then [ node ] else collectLeaves node
      ) (attrNames tree)
    );

  normalizeService =
    defaultKeys: serviceName: service:
    normalizeTree {
      inherit serviceName;
      recipientPublicKeys = service.recipientPublicKeys or defaultKeys;
      consumerUnits = service.consumerUnits or [ ];
    } service.secrets;

  normalizeServices = defaultKeys: services: mapAttrs (normalizeService defaultKeys) services;

  normalizeHost =
    {
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
      }
      // lib.mapAttrs' (user: value: lib.nameValuePair "user-${user}-services" value) users;
    };
in
{
  inherit
    collectLeaves
    normalizeHost
    normalizeService
    normalizeServices
    recipientId
    validSshPublicKey
    validateConsumerConstraints
    ;
}
