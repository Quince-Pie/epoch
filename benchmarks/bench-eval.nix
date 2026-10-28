# Head-to-Head Plane 1 Nix Evaluation Benchmark Expression
# Compares:
#   1. `epoch`     (/tmp/investigation/epoch/nix/lib.nix `mkCluster` Two-Tier Archetype + /node-overlay)
#   2. `colmena`   (/tmp/investigation/colmena/src/nix/hive/eval.nix per-node `evalConfig` + `deploymentConfig`)
#   3. `deploy-rs` (/tmp/investigation/deploy-rs/nix/transform-deploy.nix + `activate.nixos` per-node `nixosSystem`)
{
  tool ? "epoch",
  n ? 10,
  arch ? null,
}:
let
  flakeLock = builtins.fromJSON (builtins.readFile /tmp/investigation/epoch/flake.lock);
  lockedNixpkgs = flakeLock.nodes.nixpkgs.locked;
  cachedNixpkgsStorePath = "/nix/store/6nwzgfvznah5rg192x0hnl5ykchdgi59-source";
  nixpkgsTree =
    if
      (builtins ? storePath)
      && (lockedNixpkgs.narHash or "" == "sha256-rZLrzrC6i+jnTAlvPZHogKDulY7WWDEv9hJeHieO7Zw=")
      && (lockedNixpkgs.rev or "" == "3ec636362e1816bc2f0888fa0fa2c69f1bc9e504")
      && (builtins.pathExists cachedNixpkgsStorePath)
    then
      rec {
        outPath = builtins.storePath cachedNixpkgsStorePath;
        lastModified = lockedNixpkgs.lastModified;
        lastModifiedDate = "20261023163539";
        narHash = lockedNixpkgs.narHash;
        rev = lockedNixpkgs.rev;
        shortRev = builtins.substring 0 7 rev;
      }
    else
      builtins.fetchTree lockedNixpkgs;
  nixpkgs = nixpkgsTree // (import (nixpkgsTree + "/flake.nix")).outputs { self = nixpkgs; };
  inherit (nixpkgs) lib;
  system = "x86_64-linux";
  pkgs = import nixpkgs {
    inherit system;
    overlays = [ ];
  };
  epochLib = import /tmp/investigation/epoch/nix/lib.nix { inherit lib; };

  nodeIndices = lib.range 1 n;
  nodeNames = map (i: "node-${toString i}") nodeIndices;

  archetypeNames = [
    "consensus-db"
    "edge-api"
    "cache-tier"
    "worker-node"
  ];

  archetypeForIndex =
    i: builtins.elemAt archetypeNames (i - (i / 4) * 4);

  # Shared realistic NixOS service modules for the 4 archetypes (identical across all 3 tools)
  archetypeModules = {
    consensus-db =
      { config, lib, pkgs, ... }:
      {
        services.etcd.enable = true;
        services.postgresql = {
          enable = true;
          package = pkgs.postgresql_16;
        };
        networking.firewall.allowedTCPPorts = [
          2379
          2380
          5432
        ];
        boot.kernel.sysctl = {
          "vm.swappiness" = 1;
          "net.core.somaxconn" = 4096;
        };
        services.openssh.enable = true;
      };
    edge-api =
      { config, lib, pkgs, ... }:
      {
        services.nginx = {
          enable = true;
          statusPage = true;
          virtualHosts."api.internal".locations."/".proxyPass = "http://127.0.0.1:8080";
        };
        systemd.services.nginx.serviceConfig.LimitNOFILE = 65536;
        services.openssh.enable = true;
      };
    cache-tier =
      { config, lib, pkgs, ... }:
      {
        services.redis.servers."".enable = true;
        boot.kernel.sysctl."vm.overcommit_memory" = lib.mkForce 1;
        services.openssh.enable = true;
      };
    worker-node =
      { config, lib, pkgs, ... }:
      {
        services.openssh.enable = true;
        services.cron.enable = true;
      };
  };

  # 1. EPOCH: Two-Tier Archetype (evalModules 1x per archetype) + O(1) /node-overlay
  evalEpoch =
    let
      db1 = "node-1";
      db2 = if n >= 5 then "node-5" else "node-1";
      db3 = if n >= 9 then "node-9" else "node-1";
      quorumMembers = lib.unique [
        db1
        db2
        db3
      ];
      cluster = epochLib.mkCluster {
        inherit nixpkgs system;
        coordinatorPublicKeys = [
          "epoch-coord-primary:ed25519:b4f9c2d1e8a706543219fedcba9876543210fedcba9876543210fedcba987654"
        ];
        archetypes = archetypeModules;
        nodes = builtins.listToAttrs (
          map (
            i:
            let
              name = "node-${toString i}";
              arch = archetypeForIndex i;
            in
            {
              inherit name;
              value = {
                archetype = arch;
                topology = {
                  rack = "rack-${toString (i - (i / 5) * 5)}";
                  zone = "zone-${toString (i - (i / 3) * 3)}";
                  endpoint = "10.20.${toString (i / 250)}.${toString ((i - (i / 250) * 250) + 1)}:9443";
                };
                secrets.service_secret_key = {
                  owner = "root";
                  group = "root";
                  mode = "0400";
                  ciphertextEnvelope = "sealed:chacha20poly1305:node-${toString i}";
                };
                params = {
                  hostName = name;
                  ipv4 = "10.20.${toString (i / 250)}.${toString ((i - (i / 250) * 250) + 1)}/24";
                  machineId = "0102030405060708090a0b0c0d0e0f00";
                };
              };
            }
          ) nodeIndices
        );
        rollout = {
          p2pFanout = 4;
          quorums =
            if builtins.length quorumMembers >= 3 then
              {
                etcd-raft = {
                  members = quorumMembers;
                  maxUnavailable = 1;
                };
              }
            else
              { };
          waves = {
            w1-db-canary = {
              nodes = [ "node-1" ];
              dependsOn = [ ];
            };
            w2-db-member2 = {
              nodes = lib.optional (n >= 5) "node-5";
              dependsOn = [ "w1-db-canary" ];
            };
            w3-db-member3 = {
              nodes = lib.optional (n >= 9) "node-9";
              dependsOn = [ "w2-db-member2" ];
            };
            w4-fleet = {
              nodes = lib.filter (
                x:
                !(builtins.elem x [
                  "node-1"
                  "node-5"
                  "node-9"
                ])
              ) nodeNames;
              dependsOn = [ "w3-db-member3" ];
            };
          };
        };
      };
      drvPaths = cluster.nixosNodeOverlayDrvPaths;
      archetypeDrvPaths = cluster.archetypeToplevelDrvPaths;
    in
    rec {
      tool = "epoch";
      nodes = n;
      archetypesEvaluated = builtins.length archetypeNames;
      quorumValid = cluster.quorumValid;
      waveOrder = map (w: w.waveId) cluster.sortedWaves;
      inherit drvPaths archetypeDrvPaths;
      summary = {
        inherit
          tool
          nodes
          archetypesEvaluated
          quorumValid
          waveOrder
          drvPaths
          archetypeDrvPaths
          ;
      };
    };

  # 2. COLMENA: Per-Node `evalConfig` via `/tmp/investigation/colmena/src/nix/hive/eval.nix`
  evalColmena =
    let
      colmenaEval = import /tmp/investigation/colmena/src/nix/hive/eval.nix {
        hermetic = true;
        rawHive =
          {
            meta = {
              nixpkgs = pkgs;
              description = "benchmark-colmena-hive";
            };
            defaults =
              { ... }:
              {
                imports = [ /tmp/investigation/epoch/nix/archetype-module.nix ];
                boot.isContainer = true;
                system.stateVersion = "24.11";
              };
          }
          // builtins.listToAttrs (
            map (
              i:
              let
                name = "node-${toString i}";
                arch = archetypeForIndex i;
              in
              {
                inherit name;
                value =
                  { config, lib, pkgs, ... }:
                  {
                    imports = [ archetypeModules.${arch} ];
                    networking.hostName = name;
                    deployment = {
                      targetHost = "10.20.0.${toString i}";
                      tags = [
                        arch
                        "rack-${toString (i - (i / 5) * 5)}"
                      ];
                      keys.service_secret_key = {
                        text = "PLAINTEXT_SECRET_LEAK_NODE_${toString i}";
                        user = "root";
                        group = "root";
                        permissions = "0400";
                        uploadAt = "pre-activation";
                      };
                    };
                  };
              }
            ) nodeIndices
          );
      };
      deploymentConfig = colmenaEval.deploymentConfigSelected nodeNames;
      drvPaths = colmenaEval.evalSelectedDrvPaths nodeNames;
    in
    rec {
      tool = "colmena";
      nodes = n;
      inherit deploymentConfig drvPaths;
      summary = {
        inherit
          tool
          nodes
          deploymentConfig
          drvPaths
          ;
      };
    };

  # 3. DEPLOY-RS: Per-Node `nixosSystem` + `/tmp/investigation/deploy-rs/nix/transform-deploy.nix`
  evalDeployRs =
    let
      transformDeploy = import /tmp/investigation/deploy-rs/nix/transform-deploy.nix;
      rawDeploy = {
        magicRollback = true;
        autoRollback = true;
        nodes = builtins.listToAttrs (
          map (
            i:
            let
              name = "node-${toString i}";
              arch = archetypeForIndex i;
              nixosSys = nixpkgs.lib.nixosSystem {
                inherit system;
                modules = [
                  /tmp/investigation/epoch/nix/archetype-module.nix
                  archetypeModules.${arch}
                  {
                    boot.isContainer = true;
                    system.stateVersion = "24.11";
                    networking.hostName = name;
                  }
                ];
              };
            in
            {
              inherit name;
              value = {
                hostname = "10.20.0.${toString i}";
                profiles.system = {
                  user = "root";
                  path = nixosSys.config.system.build.toplevel;
                };
              };
            }
          ) nodeIndices
        );
      };
      transformed = transformDeploy rawDeploy;
      drvPaths = lib.mapAttrs (_: node: node.profiles.system.drvPath) transformed.nodes;
    in
    rec {
      tool = "deploy-rs";
      nodes = n;
      inherit drvPaths;
      summary = {
        inherit
          tool
          nodes
          drvPaths
          ;
      };
    };
in
if tool == "epoch" then
  evalEpoch
else if tool == "epoch-archetype" then
  if arch == null then
    evalEpoch.archetypeDrvPaths
  else
    (epochLib.evalArchetype {
      inherit nixpkgs pkgs system;
      archModule = archetypeModules.${arch};
    }).config.system.build.toplevel.drvPath
else if tool == "colmena" then
  evalColmena
else if tool == "deploy-rs" then
  evalDeployRs
else
  throw "Unknown benchmark tool '${tool}' (expected 'epoch', 'epoch-archetype', 'colmena', or 'deploy-rs')"
