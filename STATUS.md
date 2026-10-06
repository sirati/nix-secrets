# Development checks

The [README](README.md) and the [protocol reference](PROTOCOL.md) describe the
current behavior.

Run the Rust workspace tests in the component development shell:

```sh
nix develop --command cargo test --workspace
```

Run the packaged Rust, age, schema and NixOS VM checks:

```sh
nix flake check
```

For configurations that consume the module, see [Consumer tests](TESTING.md).
A passing result applies only to the revision and environment tested. This file
does not record a completed production rollout.
