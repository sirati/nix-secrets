# Deployments through the real operator path. `nix-secrets deploy HOST` asks
# the backend, the approving frontend (the TUI's controller and reducer,
# driven headless by nix-secrets-test-operator) claims the request, checks
# the target's host key, shows the dialog, decrypts, and deploys over SSH to
# the forwarder and the receiver. Nothing here writes a batch by hand; the
# receiver's own validation of malformed batches is in receiver-validation.nix.
{ pkgs, module }:

let
  lib = pkgs.lib;
  secretsLib = import ../lib.nix { inherit lib; };
  operatorPackage = pkgs.callPackage ../packages/test-operator.nix {
    nix-secrets = pkgs.callPackage ../packages/default.nix { };
  };
  # The operator's SSH key: deployment login and age recipient at once.
  operatorKey =
    pkgs.runCommand "nix-secrets-operator-test-key" { nativeBuildInputs = [ pkgs.openssh ]; }
      ''
        mkdir "$out"
        ssh-keygen -q -t ed25519 -N "" -C operator -f "$out/id"
      '';
  operatorPublic = lib.concatStringsSep " " (
    lib.take 2 (lib.splitString " " (builtins.readFile "${operatorKey}/id.pub"))
  );
  destination = service: name: {
    path = "/persistent/secrets/${service}/service/${name}";
    category = "service";
    owner = service;
    group = service;
    mode = "0400";
  };

  # The target's declaration, shared with the operator's schema.
  targetSecrets = {
    alpha = {
      consumerUnits = [ "alpha-consumer.service" ];
      secrets.token = {
        valueType = "key";
        externalInputRequired = true;
        destination = destination "alpha" "token";
      };
      secrets.password = {
        valueType = "password";
        destination = destination "alpha" "password";
      };
    };
    dns = {
      consumerUnits = [ "dns-consumer.service" ];
      secrets.transfer-key = {
        valueType = "key";
        valueGenerator = {
          kind = "random-bytes";
          bytes = 32;
          encoding = "base64";
        };
        destination = destination "dns" "transfer-key";
      };
      secrets.transfer-key-file = {
        valueType = "key";
        derivedFrom = {
          identifier = "machine.services.dns.transfer-key";
          prefix = "secret: ";
          suffix = "\n";
        };
        destination = destination "dns" "transfer-key-file";
      };
    };
    # Waits for a host the operator has not deployed: ns1's case.
    dns-update = {
      consumerUnits = [ "dns-update-consumer.service" ];
      secrets.update-key = {
        valueType = "key";
        derivedFrom = {
          identifier = "mail.services.stalwart.dns-update-key";
          prefix = "key: ";
          suffix = "\n";
        };
        destination = destination "dns-update" "update-key";
      };
    };
    keys.secrets.local-key.generatedSecret = {
      type = "local-ssh-key";
      output = destination "keys" "local-key" // {
        owner = "alpha";
        group = "alpha";
      };
    };
  };
  deploymentOf = host: {
    inherit host;
    destination = "nix-secrets-forward@${host}";
    port = 22;
  };
  deployment = deploymentOf "machine";
  normalize =
    hostName: services:
    secretsLib.normalizeHost {
      inherit hostName;
      deployment = deploymentOf hostName;
      socketPath = "/run/nix-secrets/backend.sock";
      defaultRecipientPublicKeys = [ operatorPublic ];
      services = lib.mapAttrs (
        _: service:
        {
          displayPath = [ ];
          recipientPublicKeys = [ operatorPublic ];
          recipientNames = [ ];
          consumerUnits = [ ];
        }
        // service
      ) services;
    };
  # The operator's evaluated schema: the target and the not yet deployed
  # mail host whose value ns1-like hosts derive from.
  schema = pkgs.writeText "nix-secrets-schema.json" (
    builtins.toJSON (
      normalize "machine" targetSecrets
      // normalize "mail" {
        stalwart.secrets.dns-update-key = {
          valueType = "key";
          valueGenerator = {
            kind = "random-bytes";
            bytes = 32;
            encoding = "base64";
          };
          destination = destination "stalwart" "dns-update-key";
        };
      }
    )
  );

  consumer = name: {
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${pkgs.coreutils}/bin/touch /run/${name}-started";
    };
  };
  systemUsers = lib.mapAttrs (name: uid: {
    isSystemUser = true;
    inherit uid;
    group = name;
  }) accounts;
  accounts = {
    alpha = 1201;
    dns = 1202;
    dns-update = 1203;
  };
in
pkgs.testers.runNixOSTest {
  name = "nix-secrets-deployment";

  nodes.machine = {
    users.users = systemUsers;
    users.groups = lib.mapAttrs (_: gid: { inherit gid; }) accounts;
        imports = [ module ];
        services.openssh.enable = true;
        # Every deployment scans the host key before connecting; the test runs
        # many in a row from one address, which sshd would otherwise penalise.
        services.openssh.settings.PerSourcePenalties = "no";
        services.nixSecrets = {
          enable = true;
          hostName = "machine";
          inherit deployment;
          defaultRecipientPublicKeys = [ operatorPublic ];
          receiver.enable = true;
          forwarder = {
            enable = true;
            authorizedKeys = [ operatorPublic ];
          };
          services = targetSecrets;
        };
        services.secretsReadyWaiter.enable = true;
        systemd.services.alpha-consumer = consumer "alpha";
        systemd.services.dns-consumer = consumer "dns";
        systemd.services.dns-update-consumer = consumer "dns-update";
        system.stateVersion = "26.05";
  };

  nodes.operator = {
    environment.systemPackages = [
      operatorPackage
      pkgs.age
      pkgs.openssh
      pkgs.git
    ];
    users.users.op = {
      isNormalUser = true;
      uid = 1000;
    };
    system.stateVersion = "26.05";
  };

  testScript = ''
    import shlex

    repo = "/home/op/repo"
    socket = "/run/user/1000/nix-secrets/backend.sock"

    def as_op(command):
        return f"runuser -u op -- env XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/op sh -c {shlex.quote(command)}"

    def deploy(*arguments):
        return as_op(
            "nix-secrets deploy --repository " + repo + " --backend-socket " + socket
            + " " + " ".join(arguments)
        )

    def start_operator(name, answer, *set_values):
        # The headless TUI; its output shows each dialog and notice.
        arguments = " ".join(f"--set {value}" for value in set_values)
        machine_log = f"/home/op/{name}.log"
        operator.succeed(as_op(
            "nix-secrets-test-operator --backend-socket " + socket
            + " --schema-file ${schema} --secret-identity /home/op/.ssh/id_ed25519"
            + " --known-hosts /home/op/.ssh/known_hosts --answer " + answer + " " + arguments
            + f" >{machine_log} 2>&1 & echo $! >/home/op/{name}.pid"
        ))
        operator.wait_until_succeeds(f"grep -q '^ready$' {machine_log}")
        return machine_log

    def stop_operator(name):
        pid = operator.succeed(f"cat /home/op/{name}.pid").strip()
        operator.execute(f"kill {pid}")
        print(operator.succeed(f"cat /home/op/{name}.log"))

    def expect_failure(command, *expected, log=None):
        output = operator.fail(command + " 2>&1")
        for text in expected:
            if text not in output:
                if log:
                    print(operator.succeed(f"cat {log}"))
                raise AssertionError(f"{text!r} not in {output!r}")
        return output

    machine.start(allow_reboot=True)
    operator.start()
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("nix-secrets-deployer.socket")
    for consumer in ["alpha", "dns", "dns-update"]:
        machine.fail(f"test -e /run/{consumer}-started")
    machine.succeed("systemctl start --no-block alpha-consumer dns-consumer dns-update-consumer")

    # The operator: a repository, a backend on it, their SSH key.
    operator.wait_for_unit("multi-user.target")
    operator.succeed("loginctl enable-linger op")
    operator.wait_until_succeeds("test -d /run/user/1000")
    operator.succeed(as_op("mkdir -p " + repo + " ~/.ssh && git init -q " + repo))
    operator.succeed("install -o op -m 0600 ${operatorKey}/id /home/op/.ssh/id_ed25519")
    operator.succeed("install -o op -m 0644 ${operatorKey}/id.pub /home/op/.ssh/id_ed25519.pub")
    operator.succeed(as_op("touch ~/.ssh/known_hosts"))
    operator.succeed(as_op(
        "nix-secrets-backend --repository " + repo + " --socket " + socket
        + " --manifest ${schema} >/home/op/backend.log 2>&1 &"
    ))
    operator.wait_until_succeeds(f"test -S {socket}")

    # Without a TUI the request is refused, and nothing is queued.
    error = operator.fail(deploy("machine") + " 2>&1")
    assert "open the nix-secrets TUI and retry" in error, error

    # 1. Missing input refuses the whole deployment before anything is sent.
    log = start_operator("refuse", "y")
    expect_failure(
        deploy("--wait", "machine"),
        "Missing values that must be entered",
        "machine.services.alpha.token (external input)",
        log=log,
    )
    stop_operator("refuse")
    dialogs = operator.succeed(f"cat {log}")
    assert "host-key=true" in dialogs, dialogs
    machine.fail("test -e /persistent/secrets/.current")
    # From now on the target's key is known and no longer asked about.
    operator.succeed(as_op("ssh-keyscan -t ed25519 machine >>~/.ssh/known_hosts 2>/dev/null"))

    # 2. The token is entered. The derived update key waits for the mail host,
    #    so a full deployment is still refused ("deploy mail first") ...
    log = start_operator("partial-refused", "y", "machine.services.alpha.token=token-one")
    expect_failure(deploy("--wait", "machine"), "deploy mail first", log=log)
    stop_operator("partial-refused")
    machine.fail("test -e /persistent/secrets/.current")

    # 3. ... and deploys everything else when the requester allows it. The
    #    skip list reaches the requester and the target keeps waiting.
    log = start_operator("partial", "y")
    output = operator.succeed(deploy("--wait", "--allow-partial", "machine"))
    assert "deployed machine" in output, output
    assert "skipped until their source host is deployed" in output, output
    assert "machine.services.dns-update.update-key" in output, output
    stop_operator("partial")
    dialogs = operator.succeed(f"cat {log}")
    assert "allow-partial=true" in dialogs and "host-key=true" not in dialogs, dialogs
    assert "skippable=[\"machine.services.dns-update.update-key\"]" in dialogs, dialogs
    machine.wait_for_unit("alpha-consumer.service")
    machine.wait_for_unit("dns-consumer.service")
    machine.succeed("runuser -u alpha -- grep -qx token-one /persistent/secrets/alpha/service/token")
    machine.succeed("test \"$(stat -c %U:%G:%a /persistent/secrets/alpha/service/token)\" = alpha:alpha:400")
    machine.fail("runuser -u dns -- cat /persistent/secrets/alpha/service/token")
    machine.succeed("test -s /persistent/secrets/alpha/service/password")
    machine.succeed("ssh-keygen -y -f /persistent/secrets/keys/service/local-key | grep -q '^ssh-ed25519 '")
    key = machine.succeed("cat /persistent/secrets/dns/service/transfer-key").strip()
    assert machine.succeed("cat /persistent/secrets/dns/service/transfer-key-file") == f"secret: {key}\n"
    machine.fail("test -e /persistent/secrets/dns-update/service/update-key")
    machine.fail("test -e /run/dns-update-started")
    # Its waiter keeps waiting, so its consumer stays stopped.
    assert machine.succeed(
        "systemctl show secrets-ready-waiter-dns-update.service -p ActiveState --value"
    ).strip() == "activating"
    audits = machine.succeed("cat /run/nix-secrets/audit/*.json")
    assert "token-one" not in audits
    # Values the target generated are now in the operator's store, encrypted.
    store = operator.succeed(f"cat {repo}/nix-secrets.toml")
    assert "machine.services.dns.transfer-key" in store and key not in store

    # 4. The TUI's `D` path is the same request; the operator rejecting it
    #    reaches the requester and changes nothing.
    first = machine.succeed("readlink /persistent/secrets/.current").strip()
    start_operator("reject", "n")
    expect_failure(deploy("--wait", "machine"), "rejected by the operator")
    stop_operator("reject")
    assert machine.succeed("readlink /persistent/secrets/.current").strip() == first

    # 5. A replaced value deploys again; without --wait the command returns
    #    at once and the TUI finishes it.
    start_operator("replace", "p", "machine.services.alpha.token=token-two")
    output = operator.succeed(deploy("machine") + " 2>&1")
    assert "approve it in the nix-secrets TUI" in output, output
    machine.wait_until_succeeds("grep -qx token-two /persistent/secrets/alpha/service/token")
    stop_operator("replace")
    assert machine.succeed("readlink /persistent/secrets/.current").strip() != first
    audits = machine.succeed("cat /run/nix-secrets/audit/*.json")
    assert '"action":"replaced"' in audits and "token-two" not in audits

    # The published generation survives a reboot and releases the consumers.
    machine.reboot()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl start alpha-consumer dns-consumer")
    machine.wait_for_unit("alpha-consumer.service")
    machine.succeed("grep -qx token-two /persistent/secrets/alpha/service/token")
    assert machine.succeed("cat /persistent/secrets/dns/service/transfer-key").strip() == key
  '';
}
