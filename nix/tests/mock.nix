# services.nixSecrets.mock installs every leaf through the production
# publisher, so the readiness waiters release their consumers, values keep
# their declared owner, group and mode, and they survive a reboot unchanged.
{ pkgs, module }:

let
  recipient = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILXG+KfyD7ATstszFLEBBeA+dfXXoD8fxhLcSjtoiqGP";
  destination = service: name: {
    path = "/persistent/secrets/${service}/service/${name}";
    category = "service";
    owner = "alpha";
    group = "alpha";
    mode = "0440";
  };
  consumer = marker: {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${pkgs.coreutils}/bin/touch /run/${marker}";
    };
  };
in
pkgs.testers.runNixOSTest {
  name = "nix-secrets-mock";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ module ];
      environment.systemPackages = [ pkgs.openssh ];
      users.groups.alpha.gid = 1201;
      users.users.alpha = {
        isSystemUser = true;
        uid = 1201;
        group = "alpha";
      };
      users.users.bob = {
        isNormalUser = true;
        uid = 1300;
      };
      services.nixSecrets = {
        enable = true;
        defaultRecipientPublicKeys = [ recipient ];
        # The receiver stays disabled: the mock needs neither it nor a backend.
        services.app = {
          consumerUnits = [ "app-consumer.service" ];
          secrets = {
            explicit = {
              valueType = "key";
              destination = destination "app" "explicit";
            };
            password = {
              valueType = "password";
              consumerConstraints = {
                cannotHandleLongerThan = 24;
                matchingRegex = "[a-z]+";
              };
              destination = destination "app" "password" // {
                mode = "0400";
              };
            };
            cookie = {
              valueType = "key";
              valueGenerator = {
                kind = "random-bytes";
                bytes = 16;
                encoding = "hex";
                prefix = "COOKIE=";
                suffix = "\n";
              };
              destination = destination "app" "cookie";
            };
            password-file = {
              valueType = "key";
              derivedFrom = {
                identifier = "machine.services.app.password";
                prefix = "[db]\npassword=";
                suffix = "\n";
              };
              destination = destination "app" "password-file";
            };
            external = {
              valueType = "key";
              externalInputRequired = true;
              destination = destination "app" "external";
            };
          };
        };
        services.keys = {
          consumerUnits = [ "keys-consumer.service" ];
          secrets.local.generatedSecret = {
            type = "local-ssh-key";
            output = destination "keys" "local" // {
              mode = "0400";
            };
          };
          secrets.authorized.destination = {
            path = "/persistent/secrets/keys/service/authorized";
            category = "service";
            owner = "root";
            group = "root";
            mode = "0400";
            contentType = "named-ssh-ed25519-public-keys";
            authorizedForUser = "backup";
          };
        };
        userServices.bob.notes.secrets.token.destination = {
          path = "/persistent/secrets/notes/service/token";
          category = "service";
          owner = "bob";
          group = "users";
          mode = "0400";
        };
        # Operator-only: never installed, and not accepted as a mock key.
        services.signing.secrets.generation-key = {
          kind = "operator";
          generator.installable = "github:example/tool#keygen";
        };
        mock = {
          enable = true;
          iUnderstandThisIsATestOnlyConfiguration = true;
          values = {
            "app.explicit" = "explicit test value\n";
            "machine.user-bob-services.notes.token" = "bob-token";
          };
        };
      };
      services.secretsReadyWaiter.enable = true;
      systemd.services.app-consumer = consumer "app-started";
      systemd.services.keys-consumer = consumer "keys-started";
      system.stateVersion = "26.05";
    };

  testScript = ''
    import json

    def stat(path):
        return machine.succeed(f"stat -L -c '%U %G %a' {path}").strip()

    def snapshot():
        return machine.succeed(
            "cd /persistent/secrets && for f in */service/*; do echo \"$f\"; cat \"$f\"; echo; done"
        )

    machine.start(allow_reboot=True)
    machine.wait_for_unit("nix-secrets-mock-install.service")
    machine.wait_for_unit("secrets-ready-waiter-app.service")
    machine.wait_for_unit("secrets-ready-waiter-keys.service")
    machine.wait_for_unit("app-consumer.service")
    machine.wait_for_unit("keys-consumer.service")
    machine.succeed("test -e /run/app-started -a -e /run/keys-started")

    # The test driver forces the system label, so the nix-secrets-mock tag
    # is checked at evaluation (nix/tests/mock-module.nix); the marker file here.
    machine.succeed("test -e /etc/nix-secrets/MOCK-SECRETS-TEST-ONLY")

    s = "/persistent/secrets"
    assert machine.succeed(f"cat {s}/app/service/explicit") == "explicit test value\n"
    assert machine.succeed(f"cat {s}/notes/service/token") == "bob-token"
    password = machine.succeed(f"cat {s}/app/service/password")
    assert len(password) == 24 and password.isalpha() and password.islower(), password
    # The derived value is its same-host source, framed exactly.
    assert machine.succeed(f"cat {s}/app/service/password-file") == f"[db]\npassword={password}\n"
    cookie = machine.succeed(f"cat {s}/app/service/cookie")
    assert cookie.startswith("COOKIE=") and cookie.endswith("\n") and len(cookie) == 7 + 32 + 1, cookie
    int(cookie[7:-1], 16)
    machine.succeed(f"test -s {s}/app/service/external")
    machine.succeed(f"ssh-keygen -y -f {s}/keys/service/local")
    authorized = machine.succeed(f"cat {s}/keys/service/authorized")
    name, algorithm, _key = authorized.split()
    assert name.startswith("mock-") and algorithm == "ssh-ed25519", authorized
    machine.fail(f"test -e {s}/signing")

    assert stat(f"{s}/app/service/explicit") == "alpha alpha 440"
    assert stat(f"{s}/app/service/password") == "alpha alpha 400"
    assert stat(f"{s}/keys/service/local") == "alpha alpha 400"
    assert stat(f"{s}/keys/service/authorized") == "root root 400"
    assert stat(f"{s}/notes/service/token") == "bob users 400"
    # Published like a real deployment: stable service links into one generation.
    assert machine.succeed(f"readlink {s}/app").strip() == ".current/app"
    versions = json.loads(machine.succeed(f"cat {s}/.current/.versions.json"))
    assert sorted(versions) == sorted([
        "machine.services.app.explicit",
        "machine.services.app.password",
        "machine.services.app.cookie",
        "machine.services.app.password-file",
        "machine.services.app.external",
        "machine.services.keys.local",
        "machine.services.keys.authorized",
        "machine.user-bob-services.notes.token",
    ]), versions
    assert versions["machine.services.app.password-file"].startswith("d-")

    # Nothing was written near a store file.
    machine.fail("find / -xdev -name 'nix-secrets.toml' -print -quit | grep .")

    before = snapshot()
    generation = machine.succeed(f"readlink {s}/.current").strip()
    machine.reboot()
    machine.wait_for_unit("nix-secrets-mock-install.service")
    machine.wait_for_unit("app-consumer.service")
    machine.wait_for_unit("keys-consumer.service")
    # Already installed: no new generation, the same values.
    assert machine.succeed(f"readlink {s}/.current").strip() == generation
    assert snapshot() == before
    assert "0 mock values (8 already installed)" in machine.succeed(
        "journalctl -b -u nix-secrets-mock-install.service"
    )
  '';
}
