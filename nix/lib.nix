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
    validateValueGenerator
    validateKeypairGenerator
    validateDerivedFrom
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
        "valueGenerator"
        "generateOnDeploy"
        "derivedFrom"
        "description"
        "humanFacing"
        "externalInputRequired"
        "identity"
        "presentation"
        "requiredForInstall"
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
        || node ? valueGenerator
        || node ? generateOnDeploy
        || node ? derivedFrom
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
    else if node ? generateOnDeploy && !builtins.isBool node.generateOnDeploy then
      throw "generateOnDeploy must be a boolean"
    else if node ? valueGenerator && (node.valueType or null) == "password" then
      throw "a password leaf uses the password generator; remove valueGenerator"
    else if node ? valueGenerator && (node.externalInputRequired or false) then
      throw "valueGenerator contradicts externalInputRequired"
    else if node ? valueGenerator && (node.destination.contentType or null) != null then
      throw "valueGenerator cannot produce a typed destination contentType"
    else if node ? derivedFrom && (node ? valueGenerator || (node.externalInputRequired or false)) then
      throw "derivedFrom excludes valueGenerator and externalInputRequired"
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
      }
      // lib.optionalAttrs (node ? valueGenerator) {
        valueGenerator = validateValueGenerator node.valueGenerator;
      }
      // lib.optionalAttrs (node ? derivedFrom) {
        derivedFrom = validateDerivedFrom node.derivedFrom;
      };

  isOperatorLeaf = node: (node.kind or null) == "operator";
  isLeaf = node: node ? destination || node ? generatedSecret || isOperatorLeaf node;

  # An operator-only value: stored encrypted for the operator, never deployed,
  # never part of a host manifest.
  normalizeOperatorLeaf =
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
        "description"
        "humanFacing"
        "identity"
        "presentation"
        "recipientPublicKeys"
        "recipientNames"
        "generator"
        "requiredForInstall"
      ];
      extra = builtins.filter (name: !(builtins.elem name allowed)) (attrNames node);
    in
    if extra != [ ] then
      throw "operator leaf has unknown fields: ${lib.concatStringsSep ", " extra}"
    else if keys == [ ] || !(builtins.all validSshPublicKey keys) then
      throw "operator leaf has no valid recipient public key"
    else
      builtins.removeAttrs node [
        "recipientPublicKeys"
        "recipientNames"
      ]
      // {
        kind = "operator";
        recipientNames = names;
        recipientPublicKeys = keys;
        recipientIds = map recipientId keys;
      }
      // lib.optionalAttrs (node ? generator) {
        generator = validateKeypairGenerator node.generator;
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
        "externalInputRequired"
        "identity"
        "presentation"
        "requiredForInstall"
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
      else if isLeaf node && !builtins.isBool (node.requiredForInstall or false) then
        throw "requiredForInstall of ${name} must be a boolean"
      else if (node.requiredForInstall or false) && node ? derivedFrom then
        throw "${name}: requiredForInstall belongs on the derivedFrom source leaf"
      else if isOperatorLeaf node && (node ? destination || node ? generatedSecret) then
        throw "operator leaf ${name} cannot have a destination or generatedSecret"
      else if isOperatorLeaf node then
        normalizeOperatorLeaf childContext node
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
        if isLeaf node then [ node ] else collectLeaves node
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

  decorateIdentity =
    host: scope: user: service: tree:
    let
      walk =
        node:
        mapAttrs (
          name: value:
          if isLeaf value then
            let
              identity = value.identity or { };
              presentation = value.presentation or { };
              unknownIdentity = builtins.filter (
                field: !(builtins.elem field [ "service" "responsibility" "namespace" "name" ])
              ) (attrNames identity);
              unknownPresentation = builtins.filter (
                field: !(builtins.elem field [ "explanation" "facing" "type" ])
              ) (attrNames presentation);
              inferredType =
                if (value.kind or null) == "operator" then "operator-key"
                else if (value.generatedSecret.type or null) == "storage-box-ssh-key" then "passphrase"
                else if (value.valueType or null) == "password" then "passphrase"
                else if (value.kind or null) == "public-info" then
                  if (value.destination.contentType or null) == "openssh-public-key" then "public-key" else "public-info"
                else if ((value.destination or (value.generatedSecret.output or { })).contentType or null) == "openssh-private-key" then "private-key"
                else if (value.valueType or null) == "key" then "key"
                else "value";
            in
            if unknownIdentity != [ ] || unknownPresentation != [ ] then
              throw "unknown identity or presentation fields for ${host}.${service}.${name}"
            else
              value
              // {
                identity = {
                  inherit host scope user service name;
                  responsibility = "main";
                  namespace = null;
                } // identity;
                presentation = {
                  explanation = value.description or "";
                  facing = if value.externalInputRequired or false then "external" else if value.humanFacing or false then "human" else "generated";
                  type = inferredType;
                } // presentation;
              }
          else
            walk value
        ) node;
    in
    walk tree;

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
      serviceDisplayPaths ? { },
    }:
    let
      system = mapAttrs (service: value: decorateIdentity hostName "system" null service value) (
        normalizeServicesNamed defaultRecipientPublicKeys defaultRecipientNames recipientPublicKeys services
      );
      users = mapAttrs (
        user: values:
        mapAttrs (service: value: decorateIdentity hostName "user" user service value) (
          normalizeServicesNamed defaultRecipientPublicKeys defaultRecipientNames recipientPublicKeys values
        )
      ) userServices;
    in
    {
      ${hostName} = {
        metadata = {
          inherit
            socketPath
            deployment
            recipientPublicKeys
            serviceDisplayPaths
            ;
        };
        services = system;
      }
      // lib.mapAttrs' (user: value: lib.nameValuePair "user-${user}-services" value) users;
    };
  # Removes operator-only leaves, for anything that reaches a host.
  withoutOperatorLeaves =
    tree:
    lib.filterAttrs (_: node: !(builtins.isAttrs node && isOperatorLeaf node)) (
      builtins.mapAttrs (
        _: node: if builtins.isAttrs node && !(isLeaf node) then withoutOperatorLeaves node else node
      ) tree
    );

  readStore =
    store:
    if store != null && builtins.pathExists store then
      builtins.fromTOML (builtins.readFile store)
    else
      { };

  # The public key the operator generated for an operator leaf, as the base64
  # text stored in plain beside its ciphertext, or null while it is unset.
  #   operatorPublicKey ./nix-secrets.toml "host.services.nmbl.generation-key"
  operatorPublicKey =
    store: identifier: ((readStore store).secrets or { }).${identifier}.public_key or null;

  missingBeforeInstallMessage =
    identifier:
    "generate/enter ${identifier} in the nix-secrets TUI first: it is required before this host can be installed";

  # operatorPublicKey for a value evaluation cannot do without: evaluation
  # fails, naming the identifier, while the key is unset.
  #   requireOperatorPublicKey ./nix-secrets.toml "host.services.nmbl.generation-key"
  requireOperatorPublicKey =
    store: identifier:
    let
      key = operatorPublicKey store identifier;
    in
    if key == null then throw (missingBeforeInstallMessage identifier) else key;

  # Whether the committed store holds a value for a leaf: public-info needs its
  # shared record, an operator leaf with a generator its public key, anything
  # else its encrypted record. A null leaf means "any record".
  isStored =
    document: identifier: leaf:
    let
      record = (document.secrets or { }).${identifier} or null;
    in
    if leaf != null && (leaf.kind or null) == "public-info" then
      (document.public_info or { }) ? ${leaf.sharedPublicId}
    else if leaf != null && isOperatorLeaf leaf && leaf ? generator then
      record != null && record ? public_key
    else
      record != null;

  # Identifiers of requiredForInstall leaves in an evaluated inventory
  # (normalizeHost's value), with the leaf.
  requiredForInstallLeaves =
    evaluatedHosts:
    let
      walk =
        prefix: tree:
        concatLists (
          map (
            name:
            let
              node = tree.${name};
              identifier = "${prefix}.${name}";
            in
            if isLeaf node then
              lib.optional (node.requiredForInstall or false) { inherit identifier; leaf = node; }
            else
              walk identifier node
          ) (attrNames tree)
        );
    in
    concatLists (
      lib.mapAttrsToList (
        host: groups:
        concatLists (
          lib.mapAttrsToList (
            group: services:
            concatLists (lib.mapAttrsToList (service: walk "${host}.${group}.${service}") services)
          ) (builtins.removeAttrs groups [ "metadata" ])
        )
      ) evaluatedHosts
    );

  # Of `required` ({ identifier; leaf; } with leaf possibly null), the
  # identifiers the store at `store` has no value for yet.
  missingBeforeInstall =
    store: required:
    let
      document = readStore store;
    in
    # Reads the store only when something is required.
    if required == [ ] then
      [ ]
    else
      map (entry: entry.identifier) (
        builtins.filter (entry: !(isStored document entry.identifier entry.leaf)) required
      );
in
{
  inherit
    isLeaf
    isOperatorLeaf
    missingBeforeInstall
    missingBeforeInstallMessage
    operatorPublicKey
    requireOperatorPublicKey
    requiredForInstallLeaves
    withoutOperatorLeaves
    collectLeaves
    normalizeHost
    normalizeService
    normalizeServices
    recipientId
    validSshPublicKey
    validateConsumerConstraints
    validateValueGenerator
    ;
}
