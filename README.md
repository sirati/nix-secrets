# nix-secrets

Edit encrypted secrets and deploy them to NixOS hosts. Nix declares recipients,
file destinations and consuming services. Values are stored with age encryption
in `nix-secrets.toml`; plaintext stays out of Nix evaluation and the Nix store.

The TUI runs where your keys are, typically a laptop. The repository and backend
can be on another machine. Secret deployment is separate from system updates.

## Install

Add the flake to your configuration:

```nix
inputs.nix-secrets.url = "github:sirati/nix-secrets";
```

On the operator machine, install `nix-secrets-1password` for 1Password support:

```nix
environment.systemPackages = [
  inputs.nix-secrets.packages.${pkgs.system}.nix-secrets-1password
];
programs._1password.enable = true;
programs._1password-gui.enable = true;
```

Enable SSH-agent and CLI integration in the 1Password desktop app. On NixOS,
the CLI must use `/run/wrappers/bin/op`. Decryption reads the matching private
key through the CLI; SSH authentication uses the agent. These are separate
permissions. See [1Password integration](AGE-PLUGIN-1P-REVIEW.md).

Other packages: `nix-secrets-age` for `--secret-identity /runtime/path/to/key`,
`nix-secrets-clipboard` for clipboard-copy support, or the default package when
runtime tools are already in `PATH`.

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

Export `secrets-backend` for each backend architecture you use. Include only
host configurations that enable nix-secrets in the inventory above.

Set `services.nixSecrets.deployment.host` and `deployment.destination` if the
hostname is not the SSH address. By default deployment uses
`nix-secrets-forward@HOST` on port 22.

See the [Nix reference](nix/README.md) for public information, target-generated
keys, derived values, operator-only keys and install prerequisites.

## Open the TUI

Local repository:

```sh
nix-secrets -- ~/infrastructure
```

Laptop TUI with the repository on a remote workstation:

```sh
nix-secrets user@workstation -- '~/infrastructure'
```

Arguments before `--` are SSH arguments. The quoted repository path is expanded
by the remote backend. The launcher evaluates the inventory and starts a backend
when needed. The workstation needs Nix and SSH access to the repository; startup
uses its `secrets-backend` flake application.

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

Changes are encrypted and saved to the repository. Commit the ciphertext file
for recovery. Profiles are stored separately in `nix-secrets-profiles.toml`.
The commit dialog refuses unrelated staged changes.

A command on the repository machine can also queue a deployment:

```sh
nix-secrets deploy --wait HOST
```

Keep the laptop TUI open. It verifies the target host key, displays the selected
values and target generation tasks, and asks for approval. Changed host keys
are rejected; unknown keys require explicit trust. Decryption occurs on the
laptop, and values reach the target through an end-to-end SSH connection.

Unset passwords can be generated on the target. External credentials must be
entered by the operator. Missing values are listed and skipped; their consuming
services keep waiting while SSH remains available for repair. Deploying secrets
does not install or update the host's NixOS system.

## Use secrets from commands

An approved backend command can request a batch through the open TUI:

```sh
nix-secrets with-secrets HOST.services.app.token \
  --reason 'Authenticate the maintenance command.' -- maintenance-command
```

This deliberately sends the approved plaintext to that command on the backend.
For stdin delivery and client-side SSH authentication, see [Command reference](COMMANDS.md).

## Reference

- [Nix declarations](nix/README.md)
- [Command reference](COMMANDS.md)
- [Storage Box bootstrap](STORAGE-BOX-BOOTSTRAP.md)
- [Trust boundaries and recovery](THREAT-MODEL.md)
- [Protocol and interoperability](PROTOCOL.md)
- [Consumer tests](TESTING.md)

## License

[MIT](LICENSE); see [third-party licenses](LICENSES.md).
