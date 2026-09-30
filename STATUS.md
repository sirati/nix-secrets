# Development checks

Current behavior is documented in the [README](README.md) and
[protocol reference](PROTOCOL.md).

Run the Rust workspace tests in the component development shell:

```sh
nix develop --command cargo test --workspace
```

Run the packaged Rust, age, schema and NixOS VM checks:

```sh
nix flake check
```

For configurations that consume the module, see [Consumer tests](TESTING.md).
Passing results apply to the revision and environment tested; this file is
not a record of a completed production rollout.
