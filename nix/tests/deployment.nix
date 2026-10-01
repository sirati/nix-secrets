# Deployments through the real operator path. `nix-secrets deploy HOST` asks
# the backend, the approving frontend (the TUI's controller and reducer,
# driven headless by nix-secrets-test-operator) claims the request, checks
# the target's host key, shows the dialog, decrypts, and deploys over SSH to
# the forwarder and the receiver. Nothing here writes a batch by hand; the
# receiver's own validation of malformed batches is in receiver-validation.nix.
{ pkgs, module }:

let
  lib = pkgs.lib;
  postDeploy = pkgs.runCommandCC "deployment-preparation-test" { nativeBuildInputs = [ pkgs.rustc ]; } ''
    mkdir -p $out/bin
    cat > hook.rs <<'EOF'
    fn main() {
        let root = std::path::Path::new("/persistent/secrets");
        assert!(root.join(".current").is_dir(), "preparation ran before publication");
        let path = root.join(".preparation-count");
        let count: u64 = std::fs::read_to_string(&path).unwrap_or_default().trim().parse().unwrap_or(0);
        std::fs::write(path, format!("{}\n", count + 1)).unwrap();
        println!("hook output must never enter the deployment protocol");
    }
    EOF
    rustc hook.rs -o $out/bin/prepare
  '';
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
  # The login key of the forwarder account, held only in the operator's
  # ssh-agent behind eight unrelated keys, as in a password manager's agent.
  agentKeys =
    pkgs.runCommand "nix-secrets-agent-test-keys" { nativeBuildInputs = [ pkgs.openssh ]; }
      ''
        mkdir "$out"
        for index in 1 2 3 4 5 6 7 8; do
          ssh-keygen -q -t ed25519 -N "" -C "unrelated-$index" -f "$out/other-$index"
        done
        ssh-keygen -q -t ed25519 -N "" -C "IT Secrets" -f "$out/forwarder"
      '';
  forwarderPublic = lib.removeSuffix "\n" (builtins.readFile "${agentKeys}/forwarder.pub");
  # The 1Password CLI as the launcher sees it: one SSH key item, the
  # operator's age identity. It logs every call; `op item list` is the call
  # that raises the prompt.
  fakeOp = pkgs.writeShellScript "op" ''
    echo "$*" >> /home/op/op.log
    case "$1 $2" in
      "item list")
        echo '[{"id":"operatoritem","title":"IT Secrets","vault":{"id":"vault1"},"additional_information":"@FINGERPRINT@"}]' ;;
      "read op://vault1/operatoritem/private key") cat /home/op/age-identity ;;
      *) exit 0 ;;
    esac
  '';
  # Runs the packaged launcher with that `op` first on PATH.
  launcher = pkgs.writeShellScript "launcher" ''
    PATH=/home/op/bin:$PATH exec ${operatorPackage}/bin/nix-secrets-1password "$@"
  '';
  # A deploying client that stops half way: it opens the deployer through
  # the forwarder, selects one value, reads the target's state, prints the
  # ssh pid and then waits to be killed, never sending a batch.
  halfClient = pkgs.writeText "half-client.py" ''
    import json, struct, subprocess, sys, time
    host, key, known_hosts = sys.argv[1:4]
    ssh = subprocess.Popen(
        ["${pkgs.openssh}/bin/ssh", "-T", "-i", key, "-o", "IdentitiesOnly=yes",
         "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
         "-o", "UserKnownHostsFile=" + known_hosts,
         "nix-secrets-forward@" + host],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    def send(kind, payload=b""):
        ssh.stdin.write(b"NSF1" + bytes([kind]) + struct.pack(">I", len(payload)) + payload)
        ssh.stdin.flush()
    def receive():
        header = ssh.stdout.read(9)
        assert header[:4] == b"NSF1", header
        return header[4], ssh.stdout.read(struct.unpack(">I", header[5:9])[0])
    send(2)  # OpenDeployer
    assert receive() == (3, b"")
    selection = json.dumps({"identifiers": ["machine.services.alpha.token"]}).encode()
    send(3, struct.pack(">I", len(selection)) + selection)
    kind, payload = receive()
    assert kind == 3 and payload, (kind, payload)
    print("ssh-pid", ssh.pid, flush=True)
    print("state-received", flush=True)
    time.sleep(600)
  '';
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
    # A. Public information with a pinned default: never sent, never blocks.
    backup.secrets.known-hosts = {
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
    # B. Filled by mail's local-ssh-key registration.
    report-authorized.secrets.fault = {
      valueType = "key";
      destination = destination "report-authorized" "fault" // {
        owner = "root";
        group = "root";
        contentType = "named-ssh-ed25519-public-keys";
        authorizedForUser = "alpha";
      };
    };
    # C. One field of an entered TOML file, framed as a Knot key.
    dyndns.secrets.credentials = {
      valueType = "key";
      externalInputRequired = true;
      destination = destination "dyndns" "credentials" // { owner = "dns"; group = "dns"; };
    };
    dyndns.secrets.knot-key = {
      valueType = "key";
      derivedFrom = {
        identifier = "machine.services.dyndns.credentials";
        tomlPath = [ "tsig" "secret_base64" ];
        prefix = "key:\n  - id: dyndns-rfc2136\n    secret: ";
        suffix = "\n";
      };
      destination = destination "dyndns" "knot-key" // { owner = "dns"; group = "dns"; };
    };
  };
  knownKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
  knownHostsInventory = builtins.toFile "test-public-info.toml" ''
    [public_info."storage-box/known-hosts"]
    version_id = "00000000000000000000000000000000"
    value = "[box.example]:23 ${knownKey}\n"
  '';
  # The owner of the shared TSIG secret, and of a private key that is only
  # ever generated on it.
  mailSecrets = {
    stalwart = {
      consumerUnits = [ "stalwart-consumer.service" ];
      secrets.dns-update-key = {
        valueType = "key";
        valueGenerator = {
          kind = "random-bytes";
          bytes = 32;
          encoding = "base64";
        };
        destination = destination "stalwart" "dns-update-key";
      };
    };
    # ns1's Storage Box case: the task takes its host key from public
    # information that has no stored value and no default, and mail has no
    # inventory file. It is listed before connecting; the rest deploys.
    box-known-hosts.secrets.known-hosts = {
      kind = "public-info";
      sharedPublicId = "box/known-hosts";
      expectedSshHost = "box.example";
      expectedSshHosts = [ "sub1.box.example" ];
      expectedSshPort = 23;
      installDefaultIfMissing = true;
      destination = {
        path = "/persistent/public-info/box/known-hosts";
        category = "public-info";
        owner = "root";
        group = "root";
        mode = "0644";
        contentType = "ssh-known-hosts";
      };
    };
    box-backup.secrets.storage-key = {
      valueType = "password";
      generatedSecret = {
        type = "storage-box-ssh-key";
        output = destination "box-backup" "storage-key" // {
          category = "backup";
          path = "/persistent/secrets/box-backup/backup/storage-key";
          owner = "stalwart";
          group = "stalwart";
        };
        bootstrap = {
          host = "sub1.box.example";
          port = 23;
          user = "sub1";
          knownHostsFile = "/persistent/public-info/box/known-hosts";
        };
      };
    };
    reporter.secrets.fault-key.generatedSecret = {
      type = "local-ssh-key";
      output = destination "reporter" "fault-key" // {
        owner = "stalwart";
        group = "stalwart";
        contentType = "openssh-private-key";
      };
      registerAt = "machine.services.report-authorized.fault";
    };
  };
  deploymentOf = host: {
    inherit host;
    destination = "nix-secrets-forward@${host}";
    port = 22;
    identityPublicKeys = [ forwarderPublic ];
    # As the module reports it from the receiver package.
    protocolVersion = 4;
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
      normalize "machine" targetSecrets // normalize "mail" mailSecrets
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
    stalwart = 1204;
  };
  target =
    name: secrets: consumers:
    {
      users.users = systemUsers;
      users.groups = lib.mapAttrs (_: gid: { inherit gid; }) accounts;
      imports = [ module ];
      services.openssh.enable = true;
      # Every deployment scans the host key before connecting; the test
      # runs many in a row from one address.
      services.openssh.settings.PerSourcePenalties = "no";
      # Fewer tries than the agent holds keys: offering them all would be
      # cut off before the forwarder key, as on ns1.
      services.openssh.settings.MaxAuthTries = 3;
      services.nixSecrets = {
        enable = true;
        hostName = name;
        deployment = deploymentOf name;
        publicInfoInventoryFile = toString knownHostsInventory;
        defaultRecipientPublicKeys = [ operatorPublic ];
        receiver.enable = true;
        receiver.postDeployCommand = "${postDeploy}/bin/prepare";
        forwarder = {
          enable = true;
          authorizedKeys = [ forwarderPublic ];
        };
        services = secrets;
      };
      services.secretsReadyWaiter.enable = true;
      systemd.services = lib.genAttrs consumers (unit: consumer unit);
      system.stateVersion = "26.05";
    };
in
pkgs.testers.runNixOSTest {
  name = "nix-secrets-deployment";

  nodes.machine = target "machine" targetSecrets [
    "alpha-consumer"
    "dns-consumer"
    "dns-update-consumer"
  ];
  nodes.mail = target "mail" mailSecrets [ "stalwart-consumer" ];

  nodes.operator = {
    environment.systemPackages = [
      operatorPackage
      pkgs.age
      pkgs.openssh
      pkgs.git
      pkgs.python3
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
        return f"runuser -u op -- env XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/op SSH_AUTH_SOCK=/home/op/agent.sock sh -c {shlex.quote(command)}"

    def deploy(*arguments):
        return as_op(
            "nix-secrets deploy --repository " + repo + " --backend-socket " + socket
            + " " + " ".join(arguments)
        )

    def start_operator(name, answer, *set_values, requests=1):
        # The headless TUI; its output shows each dialog and notice.
        arguments = " ".join(
            f"--set-file {value}" if "=/" in value else f"--set {value}" for value in set_values
        ) + f" --requests {requests}"
        machine_log = f"/home/op/{name}.log"
        operator.succeed(as_op(
            "nix-secrets-test-operator --backend-socket " + socket
            + " --schema-file ${schema} --secret-identity /home/op/age-identity"
            + " --known-hosts /home/op/.ssh/known_hosts --answer " + answer + " " + arguments
            # Decrypts through the real 1Password launcher with an `op` that
            # logs each call, so each authorization is counted.
            + " --launcher /home/op/launcher"
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
    mail.start()
    operator.start()
    mail.wait_for_unit("nix-secrets-deployer.socket")
    mail.succeed("systemctl start --no-block stalwart-consumer")
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
    # The age identity is a plain file outside ssh's default key names; the
    # SSH login key is only in the agent.
    operator.succeed("install -o op -m 0600 ${operatorKey}/id /home/op/age-identity")
    operator.succeed(as_op("ssh-agent -d -a /home/op/agent.sock >/home/op/agent.log 2>&1 &"))
    operator.wait_until_succeeds("test -S /home/op/agent.sock")
    for index in range(1, 9):
        operator.succeed(f"install -o op -m 0600 ${agentKeys}/other-{index} /home/op/other-{index}")
        operator.succeed(as_op(f"ssh-add -q /home/op/other-{index}"))
    operator.succeed("install -o op -m 0600 ${agentKeys}/forwarder /home/op/forwarder")
    operator.succeed(as_op("ssh-add -q /home/op/forwarder && rm /home/op/forwarder /home/op/other-*"))
    assert operator.succeed(as_op("ssh-add -l | wc -l")).strip() == "9"
    # Plain ssh, offering every agent key, is cut off by MaxAuthTries.
    operator.succeed(as_op("ssh-keyscan machine >~/.ssh/scan 2>/dev/null"))
    error = operator.fail(as_op(
        "ssh -o UserKnownHostsFile=~/.ssh/scan -o BatchMode=yes nix-secrets-forward@machine true 2>&1"
    ))
    assert "Too many authentication failures" in error, error

    def authorizations():
        # The launcher's first `op` call of a run raises the one 1Password
        # prompt: `op item list` for the one-key path.
        return int(operator.succeed("cat /home/op/op.log 2>/dev/null | grep -c '^item list' || true").strip())
    # The launcher next to the operator's nix-secrets, run with an `op` that
    # authorizes every request, logs it, and serves the operator's age key as
    # the one 1Password SSH key item.
    fingerprint = operator.succeed("ssh-keygen -l -E sha256 -f ${operatorKey}/id.pub").split()[1]
    operator.succeed(
        "install -D -o op -m 0755 ${fakeOp} /home/op/bin/op"
        + f" && sed -i 's|@FINGERPRINT@|{fingerprint}|' /home/op/bin/op"
        + " && install -o op -m 0755 ${launcher} /home/op/launcher"
    )
    def signatures():
        return int(operator.succeed("grep -ac 'process_sign_request2: entering' /home/op/agent.log || true").strip())
    operator.succeed(as_op("touch ~/.ssh/known_hosts"))
    operator.succeed(as_op(
        "nix-secrets-backend --repository " + repo + " --socket " + socket
        + " --manifest ${schema} >/home/op/backend.log 2>&1 &"
    ))
    operator.wait_until_succeeds(f"test -S {socket}")

    # Without a TUI the request is refused, and nothing is queued.
    error = operator.fail(deploy("machine") + " 2>&1")
    assert "open the nix-secrets TUI and retry" in error, error

    # 1. Nothing is refused for missing values: everything deployable goes,
    #    and each missing value is listed with its reason. The token needs
    #    input; the credentials file too, and the Knot key framed from it.
    log = start_operator("first", "y")
    authorized = authorizations()
    signed = signatures()
    status, output = operator.execute(deploy("--wait", "machine") + " 2>&1")
    if status != 0:
        print(machine.succeed("journalctl -u 'nix-secrets-deployer@*' --no-pager | tail -20"))
        raise AssertionError(output)
    stop_operator("first")
    # One authenticated connection for the whole deployment: one agent
    # signature, so 1Password asks once.
    assert signatures() - signed == 1, (signed, signatures())
    # And at most one 1Password authorization for every value it decrypts.
    assert authorizations() - authorized <= 1, (authorized, authorizations())
    print(operator.succeed("cat /home/op/op.log 2>/dev/null || true"))
    assert "deployed machine" in output, output
    assert "not deployed yet, machine waits for" in output, output
    assert "machine.services.alpha.token (external input)" in output, output
    assert "machine.services.report-authorized.fault (filled when mail deploy)" in output, output
    dialogs = operator.succeed(f"cat {log}")
    assert "host-key=true" in dialogs, dialogs
    # A. The public default stays; nothing was sent for it.
    machine.succeed("grep -q '\\[box.example\\]:23 ssh-ed25519 ' /persistent/public-info/storage-box/known-hosts")
    # D. The shared TSIG secret of mail was generated here, the host
    #    deployed first; the Knot file is framed from it, and the operator
    #    stored only its ciphertext under mail's identifier.
    update_key = machine.succeed("cat /persistent/secrets/dns-update/service/update-key")
    assert update_key.startswith("key: ") and update_key.endswith("\n"), update_key
    tsig = update_key[5:-1]
    store = operator.succeed(f"cat {repo}/nix-secrets.toml")
    assert "mail.services.stalwart.dns-update-key" in store and tsig not in store
    machine.fail("test -e /persistent/secrets/stalwart")
    machine.wait_for_unit("dns-update-consumer.service")
    # Generated values: installed here, stored as ciphertext.
    machine.succeed("test -s /persistent/secrets/alpha/service/password")
    machine.succeed("test $(cat /persistent/secrets/.preparation-count) -ge 1")
    machine.succeed("ssh-keygen -y -f /persistent/secrets/keys/service/local-key | grep -q '^ssh-ed25519 '")
    key = machine.succeed("cat /persistent/secrets/dns/service/transfer-key").strip()
    assert machine.succeed("cat /persistent/secrets/dns/service/transfer-key-file") == f"secret: {key}\n"
    assert "machine.services.dns.transfer-key" in store and key not in store
    machine.wait_for_unit("dns-consumer.service")
    # Values still missing keep only their own services waiting.
    machine.fail("test -e /persistent/secrets/alpha/service/token")
    machine.fail("test -e /run/alpha-started")
    assert machine.succeed(
        "systemctl show secrets-ready-waiter-alpha.service -p ActiveState --value"
    ).strip() == "activating"
    # From now on the target's key is known and no longer asked about.
    operator.succeed(as_op("ssh-keyscan -t ed25519 machine mail >>~/.ssh/known_hosts 2>/dev/null"))

    # Without the forwarder key in the agent the deployment names the key
    # and the agent instead of trying keys the target refuses.
    operator.succeed(as_op("ssh-add -L | grep 'IT Secrets' >~/forwarder.pub && ssh-add -d ~/forwarder.pub"))
    log = start_operator("no-key", "y")
    expect_failure(
        deploy("--wait", "machine"),
        "the forwarder key \"IT Secrets\" (ssh-ed25519 SHA256:",
        "is not in your ssh-agent",
        log=log,
    )
    stop_operator("no-key")
    operator.succeed("install -o op -m 0600 ${agentKeys}/forwarder /home/op/forwarder")
    operator.succeed(as_op("ssh-add -q /home/op/forwarder && rm /home/op/forwarder"))

    # 2. mail, the owner of the shared secret, receives the stored value
    #    unchanged: nothing is regenerated. Its own private key is generated
    #    on mail and registered into machine's inventory.
    signed = signatures()
    authorized = authorizations()
    log = start_operator("mail", "y", "mail.services.box-backup.storage-key=bootstrap-password")
    output = operator.succeed(deploy("--wait", "mail"))
    stop_operator("mail")
    assert "deployed mail" in output, output
    assert signatures() - signed == 1, (signed, signatures())
    assert authorizations() - authorized <= 1, (authorized, authorizations())
    # ns1's case: the Storage Box task's known_hosts has no value and no
    # default. It is listed with the path before connecting; the rest of mail
    # deployed.
    assert "mail.services.box-backup.storage-key" in output, output
    assert "/persistent/public-info/box/known-hosts is absent" in output, output
    mail.fail("test -e /persistent/secrets/box-backup/backup/storage-key")
    assert mail.succeed("cat /persistent/secrets/stalwart/service/dns-update-key") == tsig
    mail.wait_for_unit("stalwart-consumer.service")
    mail.succeed("ssh-keygen -y -f /persistent/secrets/reporter/service/fault-key | grep -q '^ssh-ed25519 '")
    # The private key never left mail; only its public half is stored.
    fault_public = mail.succeed("ssh-keygen -y -f /persistent/secrets/reporter/service/fault-key").split()[1]
    assert "PRIVATE KEY" not in operator.succeed(f"cat {repo}/nix-secrets.toml")

    # 3. The token and the dyndns credentials are entered; B's inventory now
    #    holds mail's key. Deploying machine again delivers all of them, and
    #    C frames only the TSIG field of the credentials.
    operator.succeed(as_op("printf '[tsig]\\nkey_name = \"dyndns-rfc2136\"\\nsecret_base64 = \"ZHluZG5zLXNlY3JldA==\"\\n\\n[[credentials]]\\nusername = \"router\"\\npassword = \"pw\"\\n' >~/credentials.toml"))
    # mail's registration queued a deployment of the inventory: the TUI
    # handles it first, then the requested one.
    signed = signatures()
    authorized = authorizations()
    log = start_operator(
        "second", "y",
        "machine.services.alpha.token=token-one",
        "machine.services.dyndns.credentials=/home/op/credentials.toml",
        requests=2,
    )
    output = operator.succeed(deploy("--wait", "machine"))
    stop_operator("second")
    # Storing the token and credentials encrypts only. The two deployments
    # (mail's inventory, then machine) decrypt the token, the credentials
    # the Knot key is framed from, and the inventory: one authorization
    # and one SSH signature each.
    authorized_log = operator.succeed("cat /home/op/op.log")
    assert authorizations() - authorized == 2, authorized_log
    assert signatures() - signed == 2, (signed, signatures())
    assert authorized_log.count("read op://vault1/operatoritem/private key") == authorizations(), authorized_log
    assert "not deployed yet" not in output, output
    machine.wait_for_unit("alpha-consumer.service")
    machine.succeed("runuser -u alpha -- grep -qx token-one /persistent/secrets/alpha/service/token")
    machine.succeed("test $(cat /persistent/secrets/.preparation-count) -ge 2")
    machine.succeed("test \"$(stat -c %U:%G:%a /persistent/secrets/alpha/service/token)\" = alpha:alpha:400")
    machine.fail("runuser -u dns -- cat /persistent/secrets/alpha/service/token")
    assert machine.succeed("cat /persistent/secrets/dyndns/service/knot-key") == (
        "key:\n  - id: dyndns-rfc2136\n    secret: ZHluZG5zLXNlY3JldA==\n"
    )
    machine.succeed(f"grep -q '^mail-.* ssh-ed25519 {fault_public}$' /persistent/secrets/report-authorized/service/fault")
    # The shared secret is the same on both hosts and was not regenerated.
    assert machine.succeed("cat /persistent/secrets/dns-update/service/update-key") == f"key: {tsig}\n"
    audits = machine.succeed("cat /run/nix-secrets/audit/*.json")
    assert "token-one" not in audits and "ZHluZG5z" not in audits

    # 4. The TUI's `D` path is the same request; the operator rejecting it
    #    reaches the requester and changes nothing.
    first = machine.succeed("readlink /persistent/secrets/.current").strip()
    start_operator("reject", "n")
    expect_failure(deploy("--wait", "machine"), "rejected by the operator")
    stop_operator("reject")
    assert machine.succeed("readlink /persistent/secrets/.current").strip() == first

    # A client that disappears mid-transaction: over the forwarder's SSH,
    # open the deployer, send a selection, read the target's state, then
    # kill ssh before any batch. On ns1 this left secret-deploy waiting for
    # its 20-minute timeout. It must end within seconds, publish nothing and
    # leave no staging.
    operator.succeed(
        "install -o op -m 0600 ${agentKeys}/forwarder /home/op/forwarder-key"
    )
    operator.succeed(as_op(
        "python3 ${halfClient} machine /home/op/forwarder-key /home/op/.ssh/known_hosts"
        + " >/home/op/half.log 2>&1 & echo $! >/home/op/half.pid"
    ))
    operator.wait_until_succeeds("grep -q '^state-received$' /home/op/half.log", timeout=60)
    machine.wait_until_succeeds("systemctl list-units --no-legend 'nix-secrets-deployer@*' | grep -q activating", timeout=30)
    ssh_pid = operator.succeed("sed -n 's/^ssh-pid //p' /home/op/half.log").strip()
    operator.succeed(f"kill -9 {ssh_pid}")
    machine.wait_until_fails(
        "systemctl list-units --no-legend 'nix-secrets-deployer@*' | grep -q activating",
        timeout=10,
    )
    machine.fail("pgrep -u nix-secrets-forward -f nix-secrets-forward-receiver")
    machine.fail("pgrep -f 'secret-deploy --manifest'")
    assert machine.succeed("readlink /persistent/secrets/.current").strip() == first
    machine.fail("ls -d /persistent/secrets/.generations/.staging-* 2>/dev/null | grep -q .")
    operator.succeed("rm /home/op/forwarder-key")

    # 5. A replaced value deploys again; without --wait the command returns
    #    at once and the TUI finishes it.
    start_operator("replace", "y", "machine.services.alpha.token=token-two")
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
