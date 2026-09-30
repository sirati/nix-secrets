# Consumer tests

A NixOS VM test of a configuration that uses nix-secrets should not write
secret files by hand. Enable the mock in the test configuration instead:

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
deployable leaf of the host that is not installed yet. It runs
`secret-deploy --mock-install`, which validates and publishes the values
with the same code as a real deployment: owner, group, mode, generations,
service links and versions are exactly as in production, so the readiness
waiters release their consumers normally. The unit is ordered before the
consumer units and works with or without `receiver.enable`.

`values` keys must name deployable leaves of this host; operator-only values
are rejected. For a derived leaf, an explicit value supplies the source before
framing. With `generateRest = true`, missing values are generated using the
schema's generators and content requirements. Same-host derived values reuse
their mock source. Target-local SSH keys are generated locally; Storage Box
bootstrap never contacts a real Storage Box. With `generateRest = false`,
missing values fail the installer.

Installed leaves are never replaced, so generated values stay the same across
reboots, and a fully installed host is left untouched.

The mock never reads or writes `nix-secrets.toml` and never talks to a
backend. Explicit `values` are written to the world-readable Nix store: use
only non-secret test data.

The mock must not run in production: evaluation requires the explicit
acknowledgement above. Mocked systems carry a `nix-secrets-mock` system tag,
an evaluation warning and `/etc/nix-secrets/MOCK-SECRETS-TEST-ONLY`.
The mock supports both NixOS test VMs and custom VM configurations.

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
