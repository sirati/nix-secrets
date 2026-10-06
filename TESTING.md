# Testing

## This repository

```sh
nix develop --command cargo test --workspace
nix flake check
```

## Configurations that use nix-secrets

A NixOS VM test can install test values with the mock:

```nix
pkgs.testers.runNixOSTest {
  name = "app";
  nodes.machine = {
    imports = [ nix-secrets.nixosModules.default ./machine.nix ];
    services.nixSecrets.mock = {
      enable = true;
      iUnderstandThisIsATestOnlyConfiguration = true;
      values."app.api-token" = "test-token";
    };
  };
  testScript = ''
    machine.wait_for_unit("app.service")
  '';
}
```

Keys in `values` are `SERVICE.PATH` for a machine service leaf or a full
`HOST.NAMESPACE.SERVICE.PATH` identifier. They must name deployable leaves of
the host. The values go into the Nix store, so use only test data.

At boot, `nix-secrets-mock-install.service` runs before the consumer units. It
installs every leaf that has no installed value yet through
`secret-deploy --mock-install`, the same code path as a real deployment, so
the readiness waiters behave as in production. With `generateRest = true` it
generates missing values from their generators. With `generateRest = false`
it fails if any value is missing. It never replaces an installed value, never
reads `nix-secrets.toml` and never contacts a backend or Storage Box.

A mocked system gets the `nix-secrets-mock` system tag, an evaluation warning
and `/etc/nix-secrets/MOCK-SECRETS-TEST-ONLY`.
