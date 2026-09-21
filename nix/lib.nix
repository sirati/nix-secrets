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

  normalizeLeaf = context: node:
    let
      keys = node.recipientPublicKeys or context.recipientPublicKeys;
    in
    if keys == [ ] then
      throw "secret ${node.destination.path} has no recipient public key"
    else
      builtins.removeAttrs node [ "recipientPublicKeys" ] // {
        recipientPublicKeys = keys;
        recipientIds = map recipientId keys;
        destination = validateDestination context.serviceName node.destination;
        consumerUnits = node.consumerUnits or context.consumerUnits;
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
      else if node ? destination then
        normalizeLeaf childContext node
      else
        normalizeTree childContext node
    );

  collectLeaves = tree:
    concatLists (
      map (
        name:
        let node = tree.${name};
        in if node ? destination then [ node ] else collectLeaves node
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
  inherit collectLeaves normalizeHost normalizeService normalizeServices recipientId;
}
