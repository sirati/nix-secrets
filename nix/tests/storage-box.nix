{ pkgs, module }:

let
  key =
    name:
    pkgs.runCommand name { nativeBuildInputs = [ pkgs.openssh ]; } ''
      mkdir "$out"
      ssh-keygen -q -t ed25519 -N "" -C ${name} -f "$out/id"
    '';
  hostKey = key "storage-box-host-key";
  wrongHostKey = key "wrong-storage-box-host-key";
  unrelatedKey = key "unrelated-storage-box-key";
in
pkgs.testers.runNixOSTest {
  name = "nix-secrets-storage-box-bootstrap";

  nodes.machine = import ./storage-box-fixture.nix {
    inherit
      pkgs
      module
      hostKey
      wrongHostKey
      unrelatedKey
      ;
  };

  testScript = ''
    import base64
    import json
    import os
    import textwrap
    import uuid

    socket_path = "/run/nix-secrets/deployer.sock"
    good = "machine.services.backup.storageBoxKey"
    bad = "machine.services.backup.rejectedKey"
    password = "bootstrap-password"

    def wire(value):
        body = json.dumps(value, separators=(",", ":")).encode()
        return len(body).to_bytes(4, "big") + body

    def task_script(identifier, secret, expected):
        selection = base64.b64encode(wire({
            "identifiers": [], "task_identifiers": [identifier],
        })).decode()
        batch = base64.b64encode(wire({
            "version": 1,
            "requested_identifiers": [],
            "entries": [],
            "requested_tasks": [identifier],
            "tasks": [{
                "identifier": identifier,
                "version_id": str(uuid.uuid4()),
                "password_base64": base64.b64encode(secret.encode()).decode(),
                "client_contribution_base64": base64.b64encode(
                    os.urandom(32)
                ).decode(),
            }],
        })).decode()
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
        stream = socket.socket(socket.AF_UNIX)
        stream.connect("{socket_path}")
        stream.sendall(base64.b64decode("{selection}"))
        state = receive(stream)
        assert state["hostname"] == "machine"
        assert state["secrets"] == []
        assert [item["identifier"] for item in state["tasks"]] == ["{identifier}"]
        stream.sendall(base64.b64decode("{batch}"))
        result = receive(stream)
        assert result["status"] == "{expected}", result
        stream.close()
        """)

    def run_task(identifier, secret=password, expected="applied"):
        script = base64.b64encode(
            task_script(identifier, secret, expected).encode()
        ).decode()
        machine.succeed(
            f"echo {script} | base64 -d >/root/task.py; python3 /root/task.py"
        )

    machine.start(allow_reboot=True)
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("nix-secrets-deployer.socket")
    machine.succeed("ss -lnt | grep ':23 '")

    machine.succeed("install -d -m 0700 -o storagebox -g users /var/lib/storagebox/.ssh")
    machine.succeed(
        "install -m 0600 -o storagebox -g users ${unrelatedKey}/id.pub "
        "/var/lib/storagebox/.ssh/authorized_keys"
    )
    machine.succeed("runuser -u nobody -- cat /persistent/public-info/storage-box/known-hosts | grep '\\[127.0.0.1\\]:23 ssh-ed25519 '")
    original = machine.succeed("cat /var/lib/storagebox/.ssh/authorized_keys")

    unit = "nix-secrets-deployer@probe.service"
    families = machine.succeed(
        f"systemctl show '{unit}' -p RestrictAddressFamilies --value"
    )
    assert "AF_INET" in families and "AF_INET6" in families
    environment = machine.succeed(
        f"systemctl show '{unit}' -p Environment --value"
    )
    command = machine.succeed(f"systemctl show '{unit}' -p ExecStart --value")
    assert password not in environment and password not in command

    run_task(good)
    private_key = "/persistent/secrets/backup/backup/storage-box-key"
    machine.succeed(f"test -f {private_key}")
    machine.succeed(f"test $(stat -c %a {private_key}) = 400")
    machine.succeed(f"test $(stat -c %U {private_key}) = backup")
    machine.succeed(f"test $(stat -c %G {private_key}) = backup")
    first_hash = machine.succeed(f"sha256sum {private_key}").split()[0]

    authorized = "/var/lib/storagebox/.ssh/authorized_keys"
    assert original.strip() in machine.succeed(f"cat {authorized}")
    marker = "nix-secrets:machine:machine.services.backup.storageBoxKey:"
    assert machine.succeed(f"grep -c '{marker}' {authorized}").strip() == "1"
    auth = (
        "runuser -u backup -- ssh "
        "-i /persistent/secrets/backup/backup/storage-box-key -p 23 "
        "-o BatchMode=yes -o StrictHostKeyChecking=yes "
        "-o PasswordAuthentication=no -o KbdInteractiveAuthentication=no "
        "-o UserKnownHostsFile=/persistent/public-info/storage-box/known-hosts "
        "storagebox@127.0.0.1 true"
    )
    machine.succeed(auth)

    run_task(good)
    assert machine.succeed(f"sha256sum {private_key}").split()[0] == first_hash
    assert machine.succeed(f"grep -c '{marker}' {authorized}").strip() == "1"

    run_task(bad, expected="rejected")
    machine.fail("test -e /persistent/secrets/backup/backup/rejected-key")
    assert password not in machine.succeed("grep -R -a -h . /persistent/secrets || true")
    assert password not in machine.succeed("journalctl --no-pager -a")

    machine.reboot()
    machine.wait_for_unit("sshd.service")
    assert machine.succeed(f"sha256sum {private_key}").split()[0] == first_hash
    machine.succeed("runuser -u nobody -- cat /persistent/public-info/storage-box/known-hosts | grep '\\[127.0.0.1\\]:23 ssh-ed25519 '")
    machine.succeed(auth)
  '';
}
