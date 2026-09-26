# The receiver's own validation: batches the operator never sends, written
# straight to the deployer socket. Real deployments are in deployment.nix.
{ pkgs, module }:

let
  knownKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
  knownHostsInventory = builtins.toFile "test-public-info.toml" ''
    [public_info."storage-box/known-hosts"]
    version_id = "00000000000000000000000000000000"
    value = "[box.example]:23 ${knownKey}\n"
  '';
  publicDefaultUnit = "nix-secrets-public-default-${
    builtins.substring 0 16 (builtins.hashString "sha256" "machine.services.backup.known-hosts")
  }.service";
  testKey =
    pkgs.runCommand "nix-secrets-forward-test-key"
      {
        nativeBuildInputs = [ pkgs.openssh ];
      }
      ''
        mkdir "$out"
        ssh-keygen -q -t ed25519 -N "" -C vm-test -f "$out/id"
      '';
in
pkgs.testers.runNixOSTest {
  name = "nix-secrets-receiver-validation";

  nodes.machine = { pkgs, config, ... }: {
    imports = [ module ];
    environment.systemPackages = [
      pkgs.python3
      pkgs.openssh
      config.services.nixSecrets.receiver.package
    ];
    users.groups.alpha.gid = 1201;
    users.groups.beta.gid = 1202;
    users.users.alpha = {
      isSystemUser = true;
      uid = 1201;
      group = "alpha";
    };
    users.users.beta = {
      isSystemUser = true;
      uid = 1202;
      group = "beta";
    };
    services.openssh.enable = true;
    services.nixSecrets = {
      enable = true;
      publicInfoInventoryFile = toString knownHostsInventory;
      defaultRecipientPublicKeys = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILXG+KfyD7ATstszFLEBBeA+dfXXoD8fxhLcSjtoiqGP"
      ];
      receiver.enable = true;
      forwarder = {
        enable = true;
        authorizedKeys = [ (builtins.readFile "${testKey}/id.pub") ];
      };
      services.alpha = {
        consumerUnits = [ "alpha-consumer.service" ];
        secrets.token.destination = {
          path = "/persistent/secrets/alpha/service/token";
          category = "service";
          owner = "alpha";
          group = "alpha";
          mode = "0400";
        };
      };
      services.beta = {
        consumerUnits = [ "beta-consumer.service" ];
        secrets.token.destination = {
          path = "/persistent/secrets/beta/service/token";
          category = "service";
          owner = "beta";
          group = "beta";
          mode = "0400";
        };
      };
      services.generated = {
        recipientPublicKeys = [
          (builtins.replaceStrings [ "\n" ] [ "" ] (builtins.readFile "${testKey}/id.pub"))
        ];
        secrets.cookie = {
          valueType = "key";
          valueGenerator = {
            kind = "random-bytes";
            bytes = 32;
            encoding = "base64url";
            prefix = "COOKIE=";
            suffix = "\n";
          };
          destination = {
            path = "/persistent/secrets/generated/service/cookie";
            category = "service";
            owner = "alpha";
            group = "alpha";
            mode = "0400";
          };
        };
        secrets.cookie-file = {
          valueType = "key";
          derivedFrom = {
            identifier = "machine.services.generated.cookie";
            prefix = "[cookie]\nvalue=";
            suffix = "\n";
          };
          destination = {
            path = "/persistent/secrets/generated/service/cookie-file";
            category = "service";
            owner = "alpha";
            group = "alpha";
            mode = "0400";
          };
        };
      };
      # Operator-only: must never reach the host.
      services.signing.secrets.generation-key = {
        kind = "operator";
        generator = {
          installable = "github:sirati/siratis-nmbl-bootloader?dir=sirati-nmbl/nmbl-init-rs#nmbl-sign";
          args = [ "keygen" "--alg" "ml-dsa-65" "--stdio" ];
        };
      };
      services.keys.secrets.local-key.generatedSecret = {
        type = "local-ssh-key";
        output = {
          path = "/persistent/secrets/keys/service/local-key";
          category = "service";
          owner = "alpha";
          group = "alpha";
          mode = "0400";
        };
      };
      services.authorized-keys.secrets.token.destination = {
        path = "/persistent/secrets/authorized-keys/service/token";
        category = "service";
        owner = "root";
        group = "root";
        mode = "0400";
        contentType = "named-ssh-ed25519-public-keys";
        authorizedForUser = "receiver-test";
      };
      services.backup.secrets.known-hosts = {
        kind = "public-info";
        sharedPublicId = "storage-box/known-hosts";
        expectedSshHost = "box.example";
        expectedSshPort = 23;
        installDefaultIfMissing = true;
        destination = {
          path = "/persistent/public-info/storage-box/known-hosts";
          category = "public-info";
          owner = "root";
          group = "root";
          mode = "0644";
          contentType = "ssh-known-hosts";
        };
      };
    };
    services.secretsReadyWaiter.enable = true;
    systemd.services.alpha-consumer.serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${pkgs.coreutils}/bin/touch /persistent/alpha-started";
    };
    systemd.services.beta-consumer.serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${pkgs.coreutils}/bin/touch /persistent/beta-started";
    };
    systemd.services.nmbl-mark-boot-success = {
      requires = [
        "alpha-consumer.service"
        "beta-consumer.service"
      ];
      after = [
        "alpha-consumer.service"
        "beta-consumer.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.coreutils}/bin/touch /persistent/boot-success";
      };
    };
    system.stateVersion = "26.05";
  };
  # Only the receiver's own validation: each batch here is one the operator
  # would never send, written straight to the deployer socket to check the
  # target refuses it and keeps the published generation. Real deployments go
  # through the operator in deployment.nix.
  testScript = ''
    import base64
    import json
    import textwrap
    import uuid

    socket = "/run/nix-secrets/deployer.sock"

    def entry(service, value):
        return {
            "identifier": f"machine.services.{service}.token",
            "version_id": str(uuid.uuid4()),
            "contents_base64": base64.b64encode(value.encode()).decode(),
        }

    def wire(value):
        body = json.dumps(value).encode()
        return len(body).to_bytes(4, "big") + body

    def raw_batch(entries, requested=None, expected_status="applied"):
        """Sends one batch to the receiver socket and checks its answer."""
        identifiers = requested or [item["identifier"] for item in entries]
        selection = base64.b64encode(wire({"identifiers": identifiers})).decode()
        batch = base64.b64encode(wire({
            "version": 1,
            "requested_identifiers": identifiers,
            "entries": entries,
        })).decode()
        script = textwrap.dedent(f"""
        import base64,json,socket
        def exact(stream, count):
            value = b""
            while len(value) < count:
                part = stream.recv(count - len(value))
                assert part
                value += part
            return value
        def receive(stream):
            return json.loads(exact(stream, int.from_bytes(exact(stream, 4), "big")))
        s = socket.socket(socket.AF_UNIX)
        s.connect("{socket}")
        s.sendall(base64.b64decode("{selection}"))
        state = receive(s)
        assert state["hostname"] == "machine"
        s.sendall(base64.b64decode("{batch}"))
        try:
            result = receive(s)
        except (AssertionError, ConnectionResetError):
            assert "{expected_status}" == "closed"
        else:
            assert result["status"] == "{expected_status}", result
        s.close()
        """)
        encoded = base64.b64encode(script.encode()).decode()
        machine.succeed(f"echo {encoded} | base64 -d >/root/batch.py; python3 /root/batch.py")

    def current():
        return machine.succeed("readlink /persistent/secrets/.current").strip()

    machine.start(allow_reboot=True)
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("nix-secrets-deployer.socket")

    # Operator-only values never reach the host's manifest or waiters.
    machine.fail("grep -q generation-key /etc/nix-secrets/manifest.json")
    machine.fail("systemctl cat secrets-ready-waiter-signing.service")

    # Public information: installed by default when absent, and a value for
    # another host than the declared one is refused.
    machine.succeed("systemctl show ${publicDefaultUnit} -p Result --value | grep '^success$'")
    machine.succeed("runuser -u nobody -- cat /persistent/public-info/storage-box/known-hosts | grep '\\[box.example\\]:23 ssh-ed25519 '")
    assert "secrets-ready-waiter-backup.service" not in machine.succeed("systemctl list-unit-files 'secrets-ready-waiter-*.service' --no-legend")
    old_public = machine.succeed("cat /persistent/public-info/storage-box/known-hosts")
    new_key = " ".join(machine.succeed("cat ${testKey}/id.pub").split()[:2])
    known_hosts = "machine.services.backup.known-hosts"
    public = lambda value: {
        "identifier": known_hosts,
        "version_id": str(uuid.uuid4()),
        "contents_base64": base64.b64encode(value.encode()).decode(),
    }
    raw_batch([public("[wrong.example]:23 " + new_key + "\n")], expected_status="rejected")
    assert machine.succeed("cat /persistent/public-info/storage-box/known-hosts") == old_public

    # The forwarder account runs only the relay: no shell for the key.
    machine.succeed("install -d -m 0700 /root/.ssh")
    machine.succeed("install -m 0600 ${testKey}/id /root/forward-key")
    machine.succeed("ssh-keyscan -t ed25519 localhost > /root/.ssh/known_hosts 2>/dev/null")
    machine.fail(
        "ssh -i /root/forward-key -o BatchMode=yes -o StrictHostKeyChecking=yes "
        "nix-secrets-forward@localhost true"
    )

    # A first, valid generation to compare against.
    machine.succeed("systemctl start --no-block nmbl-mark-boot-success")
    raw_batch([entry("alpha", "alpha-one"), entry("beta", "beta-one")])
    machine.wait_for_unit("nmbl-mark-boot-success.service")
    published = current()

    # A batch missing a requested value closes without publishing.
    raw_batch(
        [entry("alpha", "incomplete")],
        requested=["machine.services.alpha.token", "machine.services.beta.token"],
        expected_status="closed",
    )
    assert current() == published
    machine.succeed("grep -qx alpha-one /persistent/secrets/alpha/service/token")

    # A named-key inventory that is not a named Ed25519 key list is refused.
    raw_batch([entry("authorized-keys", "this is not a public key")], expected_status="rejected")
    raw_batch([entry("authorized-keys", "node " + new_key.replace("ssh-ed25519", "ssh-rsa") + "\n")], expected_status="rejected")
    assert current() == published
    machine.fail("test -e /persistent/secrets/authorized-keys/service/token")

    # The published generation survives a reboot.
    machine.reboot()
    machine.wait_for_unit("multi-user.target")
    assert current() == published
    machine.succeed("grep -qx alpha-one /persistent/secrets/alpha/service/token")
    machine.succeed("test -e /persistent/boot-success")
  '';
}
