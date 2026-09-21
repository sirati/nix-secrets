{ pkgs, module }:

pkgs.testers.runNixOSTest {
  name = "secrets-ready-waiter";

  nodes.machine = { pkgs, ... }: {
    imports = [ module ];
    services.openssh.enable = true;
    services.nixSecrets = {
      enable = true;
      defaultRecipientPublicKeys = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILXG+KfyD7ATstszFLEBBeA+dfXXoD8fxhLcSjtoiqGP"
      ];
      services.mail = {
        consumerUnits = [ "test-consumer.service" ];
        secrets.password.destination = {
          path = "/persistent/secrets/mail/service/password";
          category = "service";
          owner = "root";
          group = "root";
          mode = "0400";
        };
      };
    };
    services.secretsReadyWaiter.enable = true;
    systemd.services.test-consumer.serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.coreutils}/bin/touch /persistent/consumer-started";
    };
    system.stateVersion = "26.05";
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sshd.service")
    waiter = "secrets-ready-waiter-mail.service"
    for relation in ["Wants", "Requires"]:
        assert waiter not in machine.succeed(
            f"systemctl show -p {relation} --value multi-user.target"
        ).split()
    machine.succeed("systemctl start --no-block test-consumer.service")
    machine.wait_until_succeeds(
        f"test $(systemctl show -p ActiveState --value {waiter}) = activating"
    )
    assert waiter in machine.succeed(
        "systemctl show -p Requires --value test-consumer.service"
    ).split()
    machine.fail("test -e /persistent/consumer-started")
    machine.succeed(
        "gen=$(printf '%039d-%010d' 1 1); "
        "install -d -m 0711 /persistent/secrets/.generations/$gen/mail/service; "
        "ln -s .generations/$gen /persistent/secrets/.current; "
        "ln -s .current/mail /persistent/secrets/mail; "
        "install -m 0600 -o root -g root /dev/null "
        "/persistent/secrets/.generations/$gen/mail/service/password"
    )
    machine.sleep(2)
    assert machine.succeed(
        f"systemctl show -p ActiveState --value {waiter}"
    ).strip() == "activating"
    machine.fail(
        f"uid=$(awk '/^Uid:/ {{print $2}}' /proc/$(systemctl show -p MainPID "
        f"--value {waiter})/status); setpriv --reuid=$uid --clear-groups "
        "cat /persistent/secrets/mail/service/password"
    )
    machine.succeed("chmod 0400 /persistent/secrets/mail/service/password")
    machine.wait_for_unit(waiter)
    machine.wait_until_succeeds("test -e /persistent/consumer-started")
    assert machine.succeed(
        "systemctl show -p Result --value test-consumer.service"
    ).strip() == "success"
  '';
}
