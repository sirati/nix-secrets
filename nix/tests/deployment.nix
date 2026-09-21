{ pkgs, module }:

let
  testKey = pkgs.runCommand "nix-secrets-forward-test-key" {
    nativeBuildInputs = [ pkgs.openssh ];
  } ''
    mkdir "$out"
    ssh-keygen -q -t ed25519 -N "" -C vm-test -f "$out/id"
  '';
in
pkgs.testers.runNixOSTest {
  name = "nix-secrets-deployment";

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
      requires = [ "alpha-consumer.service" "beta-consumer.service" ];
      after = [ "alpha-consumer.service" "beta-consumer.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.coreutils}/bin/touch /persistent/boot-success";
      };
    };
    system.stateVersion = "26.05";
  };

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

    def deployment(entries, requested=None):
        identifiers = requested or [item["identifier"] for item in entries]
        return identifiers, {
            "version": 1,
            "requested_identifiers": identifiers,
            "entries": entries,
        }

    def protocol_script(entries, requested=None, expected_status="applied"):
        identifiers, batch = deployment(entries, requested)
        encoded_selection = base64.b64encode(wire({
            "identifiers": identifiers,
        })).decode()
        encoded_batch = base64.b64encode(wire(batch)).decode()
        return textwrap.dedent(f"""
        import base64,json,socket
        def exact(stream, count):
            value = b""
            while len(value) < count:
                part = stream.recv(count - len(value))
                assert part
                value += part
            return value
        def receive(stream):
            size = int.from_bytes(exact(stream, 4), "big")
            return json.loads(exact(stream, size))
        s = socket.socket(socket.AF_UNIX)
        s.connect("{socket}")
        s.sendall(base64.b64decode("{encoded_selection}"))
        state = receive(s)
        assert state["protocol_version"] == 1
        assert state["hostname"] == "machine"
        assert {{item["identifier"] for item in state["secrets"]}} == {set(identifiers)!r}
        for item in state["secrets"]:
            assert item["recipient_ids"]
            assert item["destination"]["path"].startswith("/persistent/secrets/")
        s.sendall(base64.b64decode("{encoded_batch}"))
        try:
            result = receive(s)
        except (AssertionError, ConnectionResetError):
            assert "{expected_status}" == "closed"
        else:
            assert result["status"] == "{expected_status}"
        s.close()
        """)

    def deploy(entries, requested=None, expected_status="applied"):
        script = protocol_script(entries, requested, expected_status)
        encoded = base64.b64encode(script.encode()).decode()
        machine.succeed(
            f"echo {encoded} | base64 -d >/root/deploy.py; python3 /root/deploy.py"
        )

    def deploy_over_ssh(entries):
        identifiers, batch = deployment(entries)
        selection = base64.b64encode(wire({"identifiers": identifiers})).decode()
        payload = base64.b64encode(wire(batch)).decode()
        script = textwrap.dedent(f"""
        import base64,json,struct,subprocess
        def frame(kind, payload=b""):
            return b"NSF1" + bytes([kind]) + struct.pack(">I", len(payload)) + payload
        def exact(stream, count):
            value = b""
            while len(value) < count:
                part = stream.read(count - len(value))
                assert part
                value += part
            return value
        def outer(stream):
            header = exact(stream, 9)
            assert header[:4] == b"NSF1"
            return header[4], exact(stream, int.from_bytes(header[5:], "big"))
        def inner(stream):
            value = b""
            while len(value) < 4 or len(value) < 4 + int.from_bytes(value[:4], "big"):
                kind, part = outer(stream)
                assert kind == 3
                value += part
            assert len(value) == 4 + int.from_bytes(value[:4], "big")
            return json.loads(value[4:])
        p = subprocess.Popen([
            "ssh", "-i", "/root/forward-key", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "nix-secrets-forward@localhost"
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write(frame(2)); p.stdin.flush()
        assert outer(p.stdout) == (3, b"")
        p.stdin.write(frame(3, base64.b64decode("{selection}"))); p.stdin.flush()
        state = inner(p.stdout)
        assert state["protocol_version"] == 1 and state["hostname"] == "machine"
        assert {{item["identifier"] for item in state["secrets"]}} == {set(identifiers)!r}
        p.stdin.write(frame(3, base64.b64decode("{payload}")) + frame(4)); p.stdin.flush()
        result = inner(p.stdout)
        assert result["status"] == "applied"
        assert outer(p.stdout) == (4, b"")
        p.stdin.close()
        assert p.wait() == 0
        """)
        command = base64.b64encode(script.encode()).decode()
        machine.succeed(
            f"echo {command} | base64 -d >/root/forward.py; python3 /root/forward.py"
        )

    machine.start(allow_reboot=True)
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("nix-secrets-deployer.socket")
    machine.succeed("install -d -m 0700 /root/.ssh")
    machine.succeed("install -m 0600 ${testKey}/id /root/forward-key")
    machine.succeed(
        "ssh-keyscan -t ed25519 localhost > /root/.ssh/known_hosts 2>/dev/null"
    )
    machine.fail(
        "ssh -i /root/forward-key -o BatchMode=yes -o StrictHostKeyChecking=yes "
        "nix-secrets-forward@localhost true"
    )

    manifest = machine.succeed("cat /etc/nix-secrets/manifest.json")
    evaluated = json.loads(manifest)
    assert "machine" in evaluated

    for waiter in [
        "secrets-ready-waiter-alpha.service",
        "secrets-ready-waiter-beta.service",
    ]:
        assert waiter not in machine.succeed(
            "systemctl show multi-user.target -p Requires -p Wants --value"
        ).split()
    machine.fail("test -e /persistent/alpha-started")
    machine.fail("test -e /persistent/boot-success")
    machine.succeed("systemctl start --no-block nmbl-mark-boot-success")

    deploy([entry("alpha", "alpha-one"), entry("beta", "beta-one")])
    machine.wait_for_unit("alpha-consumer.service")
    machine.wait_for_unit("beta-consumer.service")
    machine.wait_for_unit("nmbl-mark-boot-success.service")
    machine.succeed("test -L /persistent/secrets/.current")
    machine.succeed("test -L /persistent/secrets/alpha")
    machine.succeed("test -L /persistent/secrets/beta")
    machine.succeed(
        "runuser -u alpha -- cat /persistent/secrets/alpha/service/token | grep alpha-one"
    )
    machine.fail("runuser -u beta -- cat /persistent/secrets/alpha/service/token")
    old = machine.succeed("readlink /persistent/secrets/.current").strip()

    deploy(
        [entry("alpha", "incomplete")],
        requested=[
            "machine.services.alpha.token", "machine.services.beta.token",
        ],
        expected_status="closed",
    )
    assert machine.succeed("readlink /persistent/secrets/.current").strip() == old
    machine.succeed("grep alpha-one /persistent/secrets/alpha/service/token")

    deploy_over_ssh([
        entry("alpha", "alpha-two"), entry("beta", "beta-two")
    ])
    new = machine.succeed("readlink /persistent/secrets/.current").strip()
    assert new != old
    machine.succeed("grep alpha-two /persistent/secrets/alpha/service/token")
    machine.succeed("test -f /persistent/secrets/{}/alpha/service/token".format(old))

    machine.reboot()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("grep alpha-two /persistent/secrets/alpha/service/token")
    machine.succeed("test -e /persistent/boot-success")
  '';
}
