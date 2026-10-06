# Consumer tests

A NixOS VM test of a configuration that uses nix-secrets should not write
secret files by hand. Enable the mock in the test configuration:

```nix
services.nixSecrets.mock = {
  enable = true;                                   # test configurations only
  iUnderstandThisIsATestOnlyConfiguration = true;  # required whenever enable is set
  values = {                                       # non-secret test data
    "<service>.<leaf path>" = "…";                 # a machine service leaf
    "HOST.NAMESPACE.SERVICE.PATH" = "…";           # any leaf, e.g. a userServices one
  };
  generateRest = true;                             # default
};
```

At boot, `nix-secrets-mock-install.service` installs a value for every
deployable leaf of the host that has no installed value yet. It runs
`secret-deploy --mock-install`, which validates and publishes the values with
the same code as a real deployment. Owner, group, mode, generations, service
links and versions match production exactly, so the readiness waiters release
their consumers as usual. The unit is ordered before the consumer units and
works with or without `receiver.enable`.

Keys in `values` must name deployable leaves of this host. The mock rejects
operator-only values. For a derived leaf, an explicit value is the source
before framing. With `generateRest = true`, the mock generates missing values
from the schema's generators and content requirements. Derived values on the
same host reuse their mock source. Target-local SSH keys are generated locally.
Storage Box bootstrap never contacts a real Storage Box. With
`generateRest = false`, the installer fails if any value is missing.

The mock never replaces an installed leaf. Generated values therefore stay the
same across reboots, and the mock leaves a fully installed host untouched.

The mock never reads or writes `nix-secrets.toml` and never talks to a
backend. Explicit `values` go into the world-readable Nix store, so use only
test data that is not secret.

The mock must not run in production. Evaluation requires the explicit
acknowledgement shown above. Mocked systems carry a `nix-secrets-mock` system
tag, an evaluation warning and `/etc/nix-secrets/MOCK-SECRETS-TEST-ONLY`.
The mock works in NixOS test VMs and in custom VM configurations.

Example:

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
