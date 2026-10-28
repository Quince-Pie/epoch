# Gate 4.4 / Section 7.4.1: Deterministic NixOS VM Fault-Injection Test Harness Specification
{ pkgs, epochPackage ? null }:

pkgs.testers.runNixOSTest {
  name = "epoch-adversarial-fault-matrix";

  nodes = {
    coord =
      { ... }:
      {
        virtualisation.vlans = [ 1 ];
        imports = [ ../archetype-module.nix ];
        environment.systemPackages = pkgs.lib.optional (epochPackage != null) epochPackage;
      };
    db1 =
      { ... }:
      {
        virtualisation.vlans = [
          1
          2
        ];
        boot.loader.systemd-boot.enable = true;
        imports = [ ../archetype-module.nix ];
        environment.systemPackages = pkgs.lib.optional (epochPackage != null) epochPackage;
      };
    db2 =
      { ... }:
      {
        virtualisation.vlans = [
          1
          2
        ];
        boot.loader.systemd-boot.enable = true;
        imports = [ ../archetype-module.nix ];
        environment.systemPackages = pkgs.lib.optional (epochPackage != null) epochPackage;
      };
    db3 =
      { ... }:
      {
        virtualisation.vlans = [
          1
          2
        ];
        boot.loader.systemd-boot.enable = true;
        imports = [ ../archetype-module.nix ];
        environment.systemPackages = pkgs.lib.optional (epochPackage != null) epochPackage;
      };
    api1 =
      { ... }:
      {
        virtualisation.vlans = [
          1
          2
        ];
        boot.loader.systemd-boot.enable = true;
        imports = [ ../archetype-module.nix ];
        environment.systemPackages = pkgs.lib.optional (epochPackage != null) epochPackage;
      };
  };

  testScript = ''
    start_all()
    for m in [coord, db1, db2, db3, api1]:
        m.wait_for_unit("multi-user.target")

    # Gate 4.1: Coordinator SIGKILL mid-DAG rollout (W1 committed, W2 in BARRIER_WAIT)
    coord.succeed("epoch deploy --inject-sigkill-on-wave api-fleet &")
    api1.wait_until_succeeds("epoch-agent status | grep -q BARRIER_WAIT")
    coord.succeed("kill -9 $(pidof epoch) || true")
    api1.sleep(32)
    api1.succeed("epoch-agent status | grep -q ROLLED_BACK")
    api1.succeed("test $(readlink /run/current-system) = $(cat /var/lib/epoch/gen-prev)")
    api1.succeed("test $(readlink /run/epoch/current-secrets) = /run/epoch/secrets/gen-41")

    # Gate 4.2A: Asymmetric Management Partition (Coordinator <-> db2 dropped; Peer Mesh intact)
    db2.succeed("iptables -A INPUT -i eth0 -j DROP && iptables -A OUTPUT -o eth0 -j DROP")
    coord.succeed("epoch deploy --wave db-cohort")
    for m in [db2, db3]:
        m.wait_until_succeeds("epoch-agent status | grep -q COMMITTED")
    db2.succeed("iptables -F")

    # Gate 4.2B: Asymmetric Data-Plane Partition (db2 loses eth1 peer mesh; retains eth0 mgmt)
    db2.succeed("iptables -A INPUT -i eth1 -j DROP && iptables -A OUTPUT -o eth1 -j DROP")
    coord.fail("epoch deploy --wave db-cohort --tx-epoch 51")
    for m in [db2, db3]:
        m.succeed("epoch-agent status | grep -q ROLLED_BACK")
    db2.succeed("iptables -F")

    # Gate 4.3: Reboot into Broken Kernel / Initrd Panic -> Watchdog + systemd-boot +1 Recovery
    coord.fail("epoch deploy --node db1 --inject-initrd-panic --tx-epoch 52")
    db1.wait_for_unit("epoch-agent.service")
    db1.succeed("epoch-agent status | grep -q ROLLED_BACK")
    db1.succeed("test ! -f /boot/loader/entries/nixos-generation-*+*.conf")
    db1.succeed("test -s /run/epoch/current-secrets/pg_repl_tls_key")

    # Gate 4.4: Store Quota ENOSPC & BLAKE3 Bit-Flip Rejection
    db1.succeed("epoch-agent debug-set-quota-reserve-mib 999999")
    coord.fail("epoch deploy --node db1 --tx-epoch 53")
    db1.succeed("epoch-agent debug-set-quota-reserve-mib 512")

    # Gate 4.5: Canary Failure on db3 in Coupled Wave -> Sub-5s Cohort Rollback + Secret Zero-Wipe
    coord.fail("epoch deploy --wave db-cohort --inject-unit-fail db3:postgresql.service --tx-epoch 54")
    for m in [db2, db3]:
        m.succeed("epoch-agent status | grep -q ROLLED_BACK")
        m.succeed("test ! -d /run/epoch/secrets/gen-54")
  '';
}
