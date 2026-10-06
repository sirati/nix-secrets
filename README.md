# nix-secrets

Edit encrypted secrets and deploy them to NixOS hosts. Nix declares the
recipients, destinations and consuming services of each secret.
`nix-secrets.toml` stores the values encrypted with age to SSH public keys.
Plaintext never enters Nix evaluation or the Nix store.

The TUI runs on the machine that holds your keys. The repository and its
backend can be on another machine.

## Install

```nix
inputs.nix-secrets.url = "github:sirati/nix-secrets";
```

On the operator machine install `nix-secrets-1password` to decrypt with SSH
keys stored in 1Password, or `nix-secrets-age` to decrypt with
`--secret-identity PATH`. `nix-secrets-clipboard` adds clipboard support.

For 1Password, enable `programs._1password` and `programs._1password-gui`, and
turn on CLI integration and the SSH agent in the app. The app accepts only the
setgid `op` wrapper in `/run/wrappers/bin`. Decryption reads the one private
key that matches the ciphertext with `op read`, and SSH logins use the agent.
The app grants CLI access to the whole account for a session. Each decryption
opens its own session unless you pass `--1password-shared-session`.

## Configure a target

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

The repository flake must expose the merged inventory of every host that
enables nix-secrets, and the backend application for each backend system:

```nix
nixSecretsSchemas = nixpkgs.lib.foldl' nixpkgs.lib.recursiveUpdate { } (
  nixpkgs.lib.mapAttrsToList
    (_: host: host.config.services.nixSecrets.evaluated)
    self.nixosConfigurations
);
apps.x86_64-linux.secrets-backend =
  inputs.nix-secrets.apps.x86_64-linux.secrets-backend;
```

Deployment connects to `nix-secrets-forward@HOSTNAME` on port 22. Set
`services.nixSecrets.deployment.host`, `destination` and `port` if that is
wrong. All options are in the [Nix reference](nix/README.md).

## Run

```sh
nix-secrets -- ~/infrastructure
nix-secrets user@workstation -- '~/infrastructure'
```

Arguments before `--` go to OpenSSH. With none, the repository is local. The
launcher starts the repository's backend if none is running.

## What deploying does

The TUI sends each target only the leaves its own manifest declares, after the
operator approves. The target installs them as one atomic generation at the
declared paths, owners and modes. It generates unset passwords and leaves with
a `valueGenerator` itself and returns only their ciphertext. Values that must
be entered and are unset are skipped and listed. Their consumers keep waiting,
while SSH stays available for repair.

Deploying secrets does not build, install or switch the host's NixOS system.

## Documentation

- [Nix reference](nix/README.md)
- [Commands](COMMANDS.md)
- [Storage Box bootstrap](STORAGE-BOX-BOOTSTRAP.md)
- [Threat model](THREAT-MODEL.md)
- [Protocol](PROTOCOL.md)
- [Testing](TESTING.md)

## License

[MIT](LICENSE). See also [third-party licenses](LICENSES.md).
