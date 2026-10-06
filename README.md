# nix-secrets

Edit encrypted secrets and deploy them to NixOS hosts. Nix declares the
recipients, the file destinations and the services that consume each secret.
`nix-secrets.toml` stores the values with age encryption. Plaintext never enters
Nix evaluation or the Nix store.

The TUI runs on the machine that holds your keys, typically a laptop. The
repository and backend can be on another machine. Deploying secrets and
updating a system are separate operations.

## Install

Add the flake to your configuration:

```nix
inputs.nix-secrets.url = "github:sirati/nix-secrets";
```

For 1Password support, install `nix-secrets-1password` on the operator machine:

```nix
environment.systemPackages = [
  inputs.nix-secrets.packages.${pkgs.system}.nix-secrets-1password
];
programs._1password.enable = true;
programs._1password-gui.enable = true;
```

Enable SSH-agent and CLI integration in the 1Password desktop app. On NixOS,
the CLI must use `/run/wrappers/bin/op`. Decryption reads the matching private
key through the CLI, and SSH authentication uses the agent. These are separate
permissions. See [1Password integration](AGE-PLUGIN-1P-REVIEW.md).

Other packages are `nix-secrets-age` for `--secret-identity /runtime/path/to/key`,
`nix-secrets-clipboard` for copying to the clipboard, and the default package
for systems that already have the runtime tools in `PATH`.

## Configure a target

Import the module, declare recipients and secrets, and enable the receiver:

```nix
{ inputs, ... }: {
  imports = [ inputs.nix-secrets.nixosModules.default ];
  services.openssh.enable = true;
  services.nixSecrets = {
    enable = true;
    recipientPublicKeys.primary = "ssh-ed25519 AAAA... operator";
    defaultRecipientNames = [ "primary" ];
    receiver.enable = true;
    forwarder = {
      enable = true;
      authorizedKeys = [ "ssh-ed25519 AAAA... deployer" ];
    };
    services.app = {
      consumerUnits = [ "app.service" ];
      secrets.password = {
        valueType = "password";
        destination = {
          path = "/persistent/secrets/app/service/password";
          category = "service";
          owner = "app";
          group = "app";
          mode = "0400";
        };
      };
    };
  };
  services.secretsReadyWaiter.enable = true;
}
```

The destination owner and group must exist. Expose each host's evaluated
inventory from the repository flake:

```nix
nixSecretsSchemas = nixpkgs.lib.foldl' nixpkgs.lib.recursiveUpdate { } (
  nixpkgs.lib.mapAttrsToList
    (_: host: host.config.services.nixSecrets.evaluated)
    self.nixosConfigurations
);
apps.x86_64-linux.secrets-backend =
  inputs.nix-secrets.apps.x86_64-linux.secrets-backend;
```

Export `secrets-backend` for each backend architecture you use. The inventory
above should include only host configurations that enable nix-secrets.

If the hostname differs from the SSH address, set
`services.nixSecrets.deployment.host` and `deployment.destination`. By default
deployment connects as `nix-secrets-forward@HOST` on port 22.

The [Nix reference](nix/README.md) covers public information, keys generated on
the target, derived values, operator-only keys and install prerequisites.

## Open the TUI

Local repository:

```sh
nix-secrets -- ~/infrastructure
```

Laptop TUI with the repository on a remote workstation:

```sh
nix-secrets user@workstation -- '~/infrastructure'
```

Arguments before `--` are SSH arguments. The remote backend expands the quoted
repository path. The launcher evaluates the inventory and starts a backend if
none is running. The workstation needs Nix and SSH access to the repository.
Startup runs the workstation's `secrets-backend` flake application.

Target connections go through the workstation's existing SSH tunnel. The client
also checks the host key directly. If the direct route is unreachable, the
client shows a warning. If the keys differ, deployment stops before it sends
any secrets.

## Edit and deploy

| Key | Action |
| --- | --- |
| Enter | Edit the selected value |
| `g` / `G` | Generate one / all missing passwords |
| `r` / `c` / `p` | Reveal / copy / copy the public key |
| `d` | Delete after confirmation |
| `/` | Search |
| `F` / `T` / `S` | Filters / tree layout / saved views |
| `C` | Commit the managed TOML files |
| `D` | Deploy to a selected host |

The TUI encrypts changes and saves them to the repository. Commit the
ciphertext file so you can recover it. Profiles live separately in
`nix-secrets-profiles.toml`. The commit dialog refuses to commit if unrelated
changes are staged.

A command on the repository machine can also queue a deployment:

```sh
nix-secrets deploy --wait HOST
```

Keep the laptop TUI open. It verifies the target host key, shows the selected
values and the generation tasks for the target, and asks for approval. It
rejects changed host keys, and you must trust unknown keys explicitly. The
laptop decrypts the values and sends them to the target over an end-to-end SSH
connection.

Hosts may fill empty inventory entries. To replace an existing value or public
key, the client TUI asks for a separate "Save host-provided changes" approval.
That dialog shows the proposed changes and key fingerprints. If an entry
changes after you review it, the write fails and you must approve again.

The target can generate unset passwords. The operator must enter external
credentials. The TUI lists missing values and skips them. Their consuming
services keep waiting, and SSH stays available for repair. Deploying secrets
does not install or update the host's NixOS system.

## Use secrets from commands

An approved backend command can request a batch of values through the open TUI:

```sh
nix-secrets with-secrets HOST.services.app.token \
  --reason 'Authenticate the maintenance command.' -- maintenance-command
```

This sends the approved plaintext to that command on the backend, by design.
For stdin delivery and client-side SSH authentication, see [Command reference](COMMANDS.md).

## Reference

- [Nix declarations](nix/README.md)
- [Command reference](COMMANDS.md)
- [Storage Box bootstrap](STORAGE-BOX-BOOTSTRAP.md)
- [Trust boundaries and recovery](THREAT-MODEL.md)
- [Protocol and interoperability](PROTOCOL.md)
- [Consumer tests](TESTING.md)

## License

[MIT](LICENSE). See also [third-party licenses](LICENSES.md).
