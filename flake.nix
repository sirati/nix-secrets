{
  description = "Declarative secret management and deployment for NixOS";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      lib = import ./nix/lib.nix { inherit (nixpkgs) lib; };

      nixosModules = {
        default = import ./nix/modules/default.nix;
        backend = import ./nix/modules/backend.nix;
        forwarder = import ./nix/modules/forwarder.nix;
        receiver = import ./nix/modules/receiver.nix;
        schema = import ./nix/modules/schema.nix;
        secrets-ready-waiter = import ./nix/modules/secrets-ready-waiter.nix;
      };

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pkgsWithOnePassword = import nixpkgs {
            inherit system;
            config.allowUnfreePredicate = package: nixpkgs.lib.getName package == "1password-cli";
          };
        in
        {
          default = pkgs.callPackage ./nix/packages/default.nix { };
          nix-secrets = self.packages.${system}.default;
          nix-secrets-age = pkgs.callPackage ./nix/packages/age.nix {
            nix-secrets = self.packages.${system}.default;
          };
          nix-secrets-clipboard = pkgs.callPackage ./nix/packages/clipboard.nix {
            nix-secrets = self.packages.${system}.default;
          };
          nix-secrets-1password = pkgsWithOnePassword.callPackage ./nix/packages/one-password.nix {
            nix-secrets = self.packages.${system}.default;
          };
          secrets-ready-waiter = pkgs.callPackage ./nix/packages/secrets-ready-waiter.nix { };
        }
      );

      apps = forAllSystems (system: {
        default = self.apps.${system}.nix-secrets;
        nix-secrets = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/nix-secrets";
        };
        secret-deploy = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/secret-deploy";
        };
        secrets-backend = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/nix-secrets-backend";
        };
        forward-receiver = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/nix-secrets-forward-receiver";
        };
        nix-secrets-1password = {
          type = "app";
          program = "${self.packages.${system}.nix-secrets-1password}/bin/nix-secrets";
        };
        nix-secrets-age = {
          type = "app";
          program = "${self.packages.${system}.nix-secrets-age}/bin/nix-secrets";
        };
        nix-secrets-clipboard = {
          type = "app";
          program = "${self.packages.${system}.nix-secrets-clipboard}/bin/nix-secrets";
        };
      });

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          generated-schema =
            assert import ./nix/tests/generated-schema.nix {
              secretsLib = self.lib;
            };
            pkgs.runCommand "generated-secret-schema-test" { } "touch $out";
          consumer-constraints =
            assert import ./nix/tests/consumer-constraints.nix {
              secretsLib = self.lib;
            };
            pkgs.runCommand "consumer-constraints-test" { } "touch $out";
          real-age = pkgs.callPackage ./nix/checks/real-age.nix { };
          inherit (self.packages.${system}) secrets-ready-waiter;
          secrets-ready-waiter-vm = import ./nix/tests/secrets-ready-waiter.nix {
            inherit pkgs;
            module = self.nixosModules.default;
          };
          deployment-vm = import ./nix/tests/deployment.nix {
            inherit pkgs;
            module = self.nixosModules.default;
          };
          storage-box-vm = import ./nix/tests/storage-box.nix {
            inherit pkgs;
            module = self.nixosModules.default;
          };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt-rfc-style);
    };
}
