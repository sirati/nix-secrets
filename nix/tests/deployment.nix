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
        assert state["protocol_version"] == 2
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
        assert state["protocol_version"] == 2 and state["hostname"] == "machine"
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

    def deploy_local_key():
        identifier = "machine.services.keys.local-key"
        script = textwrap.dedent(f"""
        import base64,json,socket
        def wire(value):
            body=json.dumps(value).encode()
            return len(body).to_bytes(4,'big')+body
        def receive(sock):
            def exact(n):
                data=bytes()
                while len(data)<n:
                    chunk=sock.recv(n-len(data)); assert chunk; data+=chunk
                return data
            return json.loads(exact(int.from_bytes(exact(4),'big')))
        s=socket.socket(socket.AF_UNIX)
        s.connect('{socket}')
        s.sendall(wire({{'identifiers':[], 'task_identifiers':['{identifier}']}}))
        state=receive(s)
        assert state['tasks'][0]['type']=='local-ssh-key'
        assert state['tasks'][0]['bootstrap'] is None
        s.sendall(wire({{'version':1,'requested_identifiers':[],'entries':[],
            'requested_tasks':['{identifier}'],'tasks':[{{'identifier':'{identifier}',
            'version_id':'v1','password_base64':str(),
            'client_contribution_base64':base64.b64encode(bytes([11])*32).decode()}}]}}))
        result=receive(s)
        assert result['status']=='applied'
        assert ' ssh-ed25519 ' in result['generated_public_keys']['{identifier}']
        assert 'PRIVATE KEY' not in result['generated_public_keys']['{identifier}']
        s.close()
        """)
        encoded = base64.b64encode(script.encode()).decode()
        machine.succeed(f"echo {encoded} | base64 -d >/root/local-key.py; python3 /root/local-key.py")

    def deploy_generated():
        identifier = "machine.services.generated.cookie"
        script = textwrap.dedent(f"""
        import base64,json,socket
        def wire(value):
            body=json.dumps(value).encode()
            return len(body).to_bytes(4,'big')+body
        def receive(sock):
            def exact(n):
                data=bytes()
                while len(data)<n:
                    chunk=sock.recv(n-len(data)); assert chunk; data+=chunk
                return data
            return json.loads(exact(int.from_bytes(exact(4),'big')))
        s=socket.socket(socket.AF_UNIX)
        s.connect('{socket}')
        s.sendall(wire({{'identifiers':['{identifier}']}}))
        state=receive(s)
        assert state['protocol_version']==2
        assert json.loads(state['secrets'][0]['generator'])['kind']=='value'
        s.sendall(wire({{'version':2,'requested_identifiers':['{identifier}'],'entries':[],
            'generate':[{{'identifier':'{identifier}',
            'client_contribution_base64':base64.b64encode(bytes([13])*32).decode()}}]}}))
        result=receive(s)
        assert result['status']=='applied', result
        record=result['generated_records']['{identifier}']
        age=base64.b64decode(record['age_ciphertext_base64'])
        assert age.startswith(b'age-encryption.org/v1\\n-> ssh-ed25519 ')
        assert b'COOKIE=' not in age
        open('/root/generated.age','wb').write(age)
        print(json.dumps(record))
        s.close()
        """)
        encoded = base64.b64encode(script.encode()).decode()
        return json.loads(machine.succeed(
            f"echo {encoded} | base64 -d >/root/generated.py; python3 /root/generated.py"
        ))

    def deploy_public(value, expected_status="applied"):
        identifier = "machine.services.backup.known-hosts"
        selection = base64.b64encode(wire({"identifiers": [identifier]})).decode()
        batch = base64.b64encode(wire({"version": 1, "requested_identifiers": [identifier], "entries": [{
            "identifier": identifier,
            "version_id": str(uuid.uuid4()),
            "contents_base64": base64.b64encode(value.encode()).decode(),
        }]})).decode()
        script = textwrap.dedent(f"""
        import base64,json,socket
        def exact(sock,n):
            out=bytes()
            while len(out)<n:
                part=sock.recv(n-len(out)); assert part; out+=part
            return out
        def receive(sock):
            n=int.from_bytes(exact(sock,4),'big'); return json.loads(exact(sock,n))
        sock=socket.socket(socket.AF_UNIX); sock.connect('{socket}')
        sock.sendall(base64.b64decode('{selection}'))
        state=receive(sock)
        assert state['secrets'][0]['recipient_ids']==[]
        assert state['secrets'][0]['public_info']['shared_id']=='storage-box/known-hosts'
        sock.sendall(base64.b64decode('{batch}'))
        result=receive(sock)
        assert result['status']=='{expected_status}', result
        sock.close()
        """)
        encoded = base64.b64encode(script.encode()).decode()
        machine.succeed(f"echo {encoded} | base64 -d >/root/public-deploy.py; python3 /root/public-deploy.py")

    machine.start(allow_reboot=True)
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("nix-secrets-deployer.socket")
    machine.succeed("systemctl show ${publicDefaultUnit} -p Result --value | grep '^success$'")
    machine.fail("grep -q generation-key /etc/nix-secrets/manifest.json")
    machine.fail("systemctl cat secrets-ready-waiter-signing.service")
    machine.succeed("runuser -u nobody -- cat /persistent/public-info/storage-box/known-hosts | grep '\\[box.example\\]:23 ssh-ed25519 '")
    assert "secrets-ready-waiter-backup.service" not in machine.succeed("systemctl list-unit-files 'secrets-ready-waiter-*.service' --no-legend")
    old_public = machine.succeed("cat /persistent/public-info/storage-box/known-hosts")
    new_key = " ".join(machine.succeed("cat ${testKey}/id.pub").split()[:2])
    deploy_public("[wrong.example]:23 " + new_key + "\n", expected_status="rejected")
    assert machine.succeed("cat /persistent/public-info/storage-box/known-hosts") == old_public
    deploy_public("[box.example]:23 " + new_key + "\n")
    machine.succeed("runuser -u nobody -- cat /persistent/public-info/storage-box/known-hosts | grep '\\[box.example\\]:23 ssh-ed25519 '")
    assert machine.succeed("cat /persistent/public-info/storage-box/known-hosts") != old_public
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
    first_audits = machine.succeed("cat /run/nix-secrets/audit/*.json")
    assert '"action":"set"' in first_audits
    assert "alpha-one" not in first_audits and "beta-one" not in first_audits
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
    audits = machine.succeed("cat /run/nix-secrets/audit/*.json")
    assert '"action":"replaced"' in audits
    assert "alpha-two" not in audits and "beta-two" not in audits
    new = machine.succeed("readlink /persistent/secrets/.current").strip()
    assert new != old
    machine.succeed("grep alpha-two /persistent/secrets/alpha/service/token")
    machine.succeed("test -f /persistent/secrets/{}/alpha/service/token".format(old))
    deploy_local_key()
    machine.succeed("test -s /persistent/secrets/keys/service/local-key")
    machine.succeed("test \"$(stat -c %a /persistent/secrets/keys/service/local-key)\" = 400")
    machine.succeed("ssh-keygen -y -f /persistent/secrets/keys/service/local-key | grep '^ssh-ed25519 '")
    public_key = " ".join(machine.succeed("ssh-keygen -y -f /persistent/secrets/keys/service/local-key").split()[:2])
    deploy([entry("authorized-keys", "node-20260923T120000000Z " + public_key + "\n")])
    deploy([entry("authorized-keys", "this is not a public key")], expected_status="rejected")
    machine.succeed("grep node-20260923T120000000Z /persistent/secrets/authorized-keys/service/token")

    # The target generates an unset value, installs it, and returns only
    # ciphertext that decrypts to the installed bytes under the inner envelope.
    first = deploy_generated()
    assert not first["adopted"]
    cookie = machine.succeed("cat /persistent/secrets/generated/service/cookie")
    assert cookie.startswith("COOKIE=") and cookie.endswith("\n") and len(cookie) == 7 + 43 + 1
    machine.succeed("test \"$(stat -c %a /persistent/secrets/generated/service/cookie)\" = 400")
    inner = machine.succeed("${pkgs.age}/bin/age -d -i /root/forward-key /root/generated.age | base64 -w0")
    assert base64.b64decode(inner).endswith(cookie.encode())
    # A retry after a lost store write re-encrypts the installed value.
    second = deploy_generated()
    assert second["adopted"] and second["version_id_base64"] == first["version_id_base64"]
    assert machine.succeed("cat /persistent/secrets/generated/service/cookie") == cookie

    machine.reboot()
    machine.wait_for_unit("multi-user.target")
    assert machine.succeed("cat /persistent/public-info/storage-box/known-hosts") != old_public
    machine.succeed("grep alpha-two /persistent/secrets/alpha/service/token")
    machine.succeed("test -e /persistent/boot-success")
  '';
}
