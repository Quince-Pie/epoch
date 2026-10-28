# Plane 1 & Plane 3: Shared Service Archetype Indirection & Early-Boot Secret Unsealing Module
{ config, lib, pkgs, ... }:

let
  cfg = config.services.epoch;
in
{
  options.services.epoch = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable the EPOCH late-bound /node-overlay and zero-trust secret agent.";
    };

    agentPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "Optional package providing the epoch-agent binary.";
    };

    listenEndpoint = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0:9443";
      description = "QUIC/mTLS P2P and control-plane listen endpoint (ALPN = epoch-p2p/1).";
    };
  };

  config = lib.mkIf cfg.enable {
    # Plane 1.1: Late-bound /node-overlay activation script so the heavy NixOS module fixpoint
    # is evaluated and built ONCE per service archetype and parameterized in O(1) per node.
    system.activationScripts.epoch-node-overlay = {
      deps = [ "etc" ];
      text = ''
        OVERLAY_DIR="$(realpath "''${EPOCH_STAGE_ROOT:-/nix/var/nix/profiles/system}/node-overlay" 2>/dev/null || true)"
        if [ -d "$OVERLAY_DIR/etc" ]; then
          mkdir -p /etc/epoch
          ln -sfn "$OVERLAY_DIR/etc/hostname" /etc/hostname
          ln -sfn "$OVERLAY_DIR/etc/machine-id" /etc/machine-id
          ln -sfn "$OVERLAY_DIR/etc/epoch-node.json" /etc/epoch/node.json
        fi
      '';
    };

    # Plane 3.3: 100% coordinator-free Stage-2 early-boot unsealing onto unswappable ramfs
    systemd.services.epoch-early-unseal = {
      description = "EPOCH Early-Boot Hardware/Host Secret Unsealing (ramfs)";
      wantedBy = [ "sysinit.target" ];
      before = [
        "sysinit.target"
        "network-pre.target"
        "systemd-udevd.service"
      ];
      restartIfChanged = false;
      stopIfChanged = false;
      unitConfig.DefaultDependencies = false;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        OOMScoreAdjust = -1000;
        ExecStart = pkgs.writeShellScript "epoch-early-unseal" ''
          mkdir -p /run/epoch/secrets
          chmod 0700 /run/epoch/secrets
          if ! grep -q " /run/epoch/secrets ramfs " /proc/mounts 2>/dev/null; then
            mount -t ramfs -o nosuid,nodev,noexec,mode=0700 epoch-secrets /run/epoch/secrets || true
          fi
          if [ -x /run/booted-system/sw/bin/epoch-agent ]; then
            /run/booted-system/sw/bin/epoch-agent unseal-boot \
              --system-root /run/booted-system \
              --ramfs-root /run/epoch/secrets
          fi
        '';
      };
    };

    # Plane 4: Target daemon locked in RAM (mlockall) and immune to OOM killer
    systemd.services.epoch-agent = {
      description = "EPOCH Transactional Activation, Lease Barrier & QUIC P2P Agent";
      after = [
        "epoch-early-unseal.service"
        "network.target"
      ];
      requires = [ "epoch-early-unseal.service" ];
      wantedBy = [ "multi-user.target" ];
      restartIfChanged = false;
      stopIfChanged = false;
      serviceConfig = {
        Type = "simple";
        Restart = "always";
        RestartSec = "1s";
        OOMScoreAdjust = -1000;
        LimitMEMLOCK = "infinity";
        ExecStart =
          if cfg.agentPackage != null then
            "${cfg.agentPackage}/bin/epoch-agent daemon --listen ${lib.escapeShellArg cfg.listenEndpoint}"
          else
            "/run/current-system/sw/bin/epoch-agent daemon --listen ${lib.escapeShellArg cfg.listenEndpoint}";
      };
    };
  };
}
