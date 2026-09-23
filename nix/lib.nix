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
    validatePublicDestination
    validSshPublicKey
    validateConsumerConstraints
    validateGeneratedSecret
    ;

  normalizeLeaf =
    context: node:
    let
      names = node.recipientNames or (if node ? recipientPublicKeys then [ ] else context.recipientNames);
      keys =
        if names == [ ] then
          node.recipientPublicKeys or context.recipientPublicKeys
        else
          map (
            name: context.namedRecipientPublicKeys.${name} or (throw "unknown recipient name: ${name}")
          ) names;
      allowed = [
        "kind"
        "sharedPublicId"
        "expectedSshHost"
        "expectedSshPort"
        "installDefaultIfMissing"
        "destination"
        "recipientPublicKeys"
        "recipientNames"
        "consumerUnits"
        "valueType"
        "consumerConstraints"
        "description"
        "humanFacing"
      ];
      extra = builtins.filter (name: !(builtins.elem name allowed)) (attrNames node);
    in
    if extra != [ ] then
      throw "secret leaf has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if (node.kind or "secret") == "public-info" then
      if !(node ? sharedPublicId && node ? expectedSshHost && node ? expectedSshPort) then
        throw "public-info requires sharedPublicId, expectedSshHost, and expectedSshPort"
      else if
        node ? recipientNames
        || node ? recipientPublicKeys
        || node ? valueType
        || node ? consumerConstraints
      then
        throw "public-info cannot have encryption recipients or a private value type"
      else
        builtins.removeAttrs node [
          "recipientPublicKeys"
          "recipientNames"
        ]
        // {
          kind = "public-info";
          recipientNames = [ ];
          recipientPublicKeys = [ ];
          recipientIds = [ ];
          destination = validatePublicDestination node.sharedPublicId node.destination;
          consumerUnits = node.consumerUnits or context.consumerUnits;
        }
    else if keys == [ ] then
      throw "secret ${node.destination.path} has no recipient public key"
    else if
      node ? valueType
      && !(builtins.elem node.valueType [
        "password"
        "key"
      ])
    then
      throw "unsupported secret valueType"
    else if node ? consumerConstraints && (node.valueType or null) != "password" then
      throw "consumerConstraints requires valueType=password"
    else
      builtins.removeAttrs node [
        "recipientPublicKeys"
        "recipientNames"
      ]
      // {
        kind = "secret";
        recipientNames = names;
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
      names = node.recipientNames or (if node ? recipientPublicKeys then [ ] else context.recipientNames);
      keys =
        if names == [ ] then
          node.recipientPublicKeys or context.recipientPublicKeys
        else
          map (
            name: context.namedRecipientPublicKeys.${name} or (throw "unknown recipient name: ${name}")
          ) names;
      generated = validateGeneratedSecret context.serviceName node.generatedSecret;
      allowed = [
        "generatedSecret"
        "recipientPublicKeys"
        "recipientNames"
        "consumerUnits"
        "valueType"
        "consumerConstraints"
        "description"
        "humanFacing"
      ];
      extra = builtins.filter (name: !(builtins.elem name allowed)) (attrNames node);
    in
    if extra != [ ] then
      throw "generated secret leaf has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if keys == [ ] || !(builtins.all validSshPublicKey keys) then
      throw "generated secret ${generated.output.path} has no valid recipient public key"
    else if
      node ? valueType
      && !(builtins.elem node.valueType [
        "password"
        "key"
      ])
    then
      throw "unsupported secret valueType"
    else if node ? consumerConstraints && (node.valueType or null) != "password" then
      throw "consumerConstraints requires valueType=password"
    else
      builtins.removeAttrs node [
        "recipientPublicKeys"
        "recipientNames"
      ]
      // {
        kind = "generated";
        recipientNames = names;
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
      inheritedNames =
        tree._recipientNames or (if tree ? _recipientPublicKeys then [ ] else context.recipientNames);
      inheritedKeys = tree._recipientPublicKeys or context.recipientPublicKeys;
      childContext = context // {
        recipientPublicKeys = inheritedKeys;
        recipientNames = inheritedNames;
      };
      names = builtins.filter (
        name:
        !(builtins.elem name [
          "_recipientPublicKeys"
          "_recipientNames"
        ])
      ) (attrNames tree);
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

  normalizeServiceNamed =
    defaultKeys: defaultNames: namedKeys: serviceName: service:
    normalizeTree {
      inherit serviceName;
      recipientPublicKeys = service.recipientPublicKeys or defaultKeys;
      recipientNames =
        service.recipientNames or (if service ? recipientPublicKeys then [ ] else defaultNames);
      namedRecipientPublicKeys = namedKeys;
      consumerUnits = service.consumerUnits or [ ];
    } service.secrets;

  normalizeServicesNamed =
    defaultKeys: defaultNames: namedKeys: services:
    mapAttrs (normalizeServiceNamed defaultKeys defaultNames namedKeys) services;
  normalizeService =
    defaultKeys: serviceName: service:
    normalizeServiceNamed defaultKeys [ ] { } serviceName service;
  normalizeServices = defaultKeys: services: mapAttrs (normalizeService defaultKeys) services;

  normalizeHost =
    {
      hostName,
      socketPath,
      deployment,
      defaultRecipientPublicKeys ? [ ],
      recipientPublicKeys ? { },
      defaultRecipientNames ? [ ],
      services ? { },
      userServices ? { },
    }:
    let
      system =
        normalizeServicesNamed defaultRecipientPublicKeys defaultRecipientNames recipientPublicKeys
          services;
      users = mapAttrs (
        _: normalizeServicesNamed defaultRecipientPublicKeys defaultRecipientNames recipientPublicKeys
      ) userServices;
    in
    {
      ${hostName} = {
        metadata = { inherit socketPath deployment recipientPublicKeys; };
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
