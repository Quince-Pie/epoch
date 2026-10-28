# Pure-Nix Evaluation & Static Invariant Test Suite for `epoch.lib.mkCluster` (DESIGN.md §7.2)
{ nixpkgs, epochLib }:

let
  inherit (nixpkgs) lib;

  prodCluster = epochLib.mkCluster {
    inherit nixpkgs;
    system = "x86_64-linux";

    coordinatorPublicKeys = [
      "epoch-coord-primary:ed25519:b4f9c2d1e8a706543219fedcba9876543210fedcba9876543210fedcba987654"
    ];

    evalPolicy = {
      maxWorkers = 4;
      workerMaxRssMiB = 768;
    };

    archetypes = {
      consensus-db =
        { config, lib, pkgs, ... }:
        {
          services.etcd.enable = true;
          services.postgresql = {
            enable = true;
            package = pkgs.postgresql_16;
          };
          systemd.services.postgresql.serviceConfig.LoadCredential = [
            "repl_tls_key:/run/epoch/current-secrets/pg_repl_tls_key"
          ];
        };

      edge-api =
        { config, lib, pkgs, ... }:
        {
          services.nginx.enable = true;
          systemd.services.nginx.serviceConfig.LoadCredential = [
            "jwt_signing_key:/run/epoch/current-secrets/jwt_signing_key"
          ];
        };
    };

    nodes = {
      db-1 = {
        archetype = "consensus-db";
        topology = {
          rack = "rack-a";
          zone = "us-east-1a";
          endpoint = "10.10.1.11:9443";
        };
        identity = {
          hostEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb9 db-1";
          tpm2PcrMask = [
            0
            2
            7
          ];
        };
        secrets.pg_repl_tls_key = {
          owner = "postgres";
          group = "postgres";
          mode = "0400";
        };
        params = {
          hostName = "db-1";
          ipv4 = "10.10.1.11/24";
          machineId = "0102030405060708090a0b0c0d0e0f01";
        };
      };

      db-2 = {
        archetype = "consensus-db";
        topology = {
          rack = "rack-b";
          zone = "us-east-1b";
          endpoint = "10.10.2.12:9443";
        };
        identity = {
          hostEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHc8 db-2";
          tpm2PcrMask = [
            0
            2
            7
          ];
        };
        secrets.pg_repl_tls_key = {
          owner = "postgres";
          group = "postgres";
          mode = "0400";
        };
        params = {
          hostName = "db-2";
          ipv4 = "10.10.2.12/24";
          machineId = "0102030405060708090a0b0c0d0e0f02";
        };
      };

      db-3 = {
        archetype = "consensus-db";
        topology = {
          rack = "rack-c";
          zone = "us-east-1c";
          endpoint = "10.10.3.13:9443";
        };
        identity = {
          hostEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJd7 db-3";
          tpm2PcrMask = [
            0
            2
            7
          ];
        };
        secrets.pg_repl_tls_key = {
          owner = "postgres";
          group = "postgres";
          mode = "0400";
        };
        params = {
          hostName = "db-3";
          ipv4 = "10.10.3.13/24";
          machineId = "0102030405060708090a0b0c0d0e0f03";
        };
      };

      api-1 = {
        archetype = "edge-api";
        topology = {
          rack = "rack-a";
          zone = "us-east-1a";
          endpoint = "10.10.1.21:9443";
        };
        identity = {
          hostEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKe6 api-1";
          tpm2PcrMask = [
            0
            2
            7
          ];
        };
        secrets.jwt_signing_key = {
          owner = "nginx";
          group = "nginx";
          mode = "0400";
        };
        params = {
          hostName = "api-1";
          ipv4 = "10.10.1.21/24";
          machineId = "0102030405060708090a0b0c0d0e0f04";
        };
      };
    };

    rollout = {
      p2pFanout = 4;
      quorums.etcd-cluster = {
        members = [
          "db-1"
          "db-2"
          "db-3"
        ];
        maxUnavailable = 1;
      };
      waves = {
        db-canary = {
          nodes = [ "db-1" ];
          dependsOn = [ ];
          quorumRef = "etcd-cluster";
          leaseTtlSec = 30;
          rebootLeaseTtlSec = 120;
          probes = {
            requiredSystemdUnits = [
              "etcd.service"
              "postgresql.service"
            ];
            tcpEndpoints = [
              "127.0.0.1:2379"
              "127.0.0.1:5432"
            ];
            peerMeshQuorum = 1;
            forbidKmsgPatterns = [
              "Oops:"
              "BUG:"
              "Out of memory: Killed process"
            ];
          };
        };
        db-cohort = {
          nodes = [
            "db-2"
            "db-3"
          ];
          dependsOn = [ "db-canary" ];
          maxUnavailable = 0;
          leaseTtlSec = 30;
          rebootLeaseTtlSec = 120;
          probes = {
            requiredSystemdUnits = [
              "etcd.service"
              "postgresql.service"
            ];
            tcpEndpoints = [
              "127.0.0.1:2379"
              "127.0.0.1:5432"
            ];
            peerMeshQuorum = 2;
            forbidKmsgPatterns = [
              "Oops:"
              "BUG:"
              "Out of memory: Killed process"
            ];
          };
        };
        api-fleet = {
          nodes = [ "api-1" ];
          dependsOn = [ "db-cohort" ];
          leaseTtlSec = 20;
          rebootLeaseTtlSec = 90;
          probes = {
            requiredSystemdUnits = [ "nginx.service" ];
            httpChecks = [
              {
                url = "http://127.0.0.1:8080/healthz";
                status = 200;
              }
            ];
            peerMeshQuorum = 1;
            forbidKmsgPatterns = [
              "Oops:"
              "BUG:"
              "Out of memory: Killed process"
            ];
          };
        };
      };
    };
  };

  # Negative Test 1: Cycle in wave DAG must fail evaluation
  cycleRejected =
    !(
      (builtins.tryEval (
        builtins.deepSeq (epochLib.toposortWaves {
          w1 = {
            nodes = [ "a" ];
            dependsOn = [ "w2" ];
          };
          w2 = {
            nodes = [ "b" ];
            dependsOn = [ "w1" ];
          };
        }) true
      )).success
    );

  # Negative Test 2: Violating quorum maxUnavailable > floor((|Q|-1)/2) must fail evaluation
  quorumMinorityRejected =
    !(
      (builtins.tryEval (
        builtins.deepSeq (epochLib.validateQuorums
          {
            raft = {
              members = [
                "n1"
                "n2"
                "n3"
              ];
              maxUnavailable = 2; # Invalid: 2 > floor((3-1)/2) = 1
            };
          }
          {
            w1 = {
              nodes = [ "n1" ];
            };
          }
        ) true
      )).success
    );

  # Negative Test 3: Wave concurrently targeting 2 members of a 3-node quorum must fail evaluation
  waveQuorumOverlapRejected =
    !(
      (builtins.tryEval (
        builtins.deepSeq (epochLib.validateQuorums
          {
            raft = {
              members = [
                "n1"
                "n2"
                "n3"
              ];
              maxUnavailable = 1;
            };
          }
          {
            w1 = {
              nodes = [
                "n1"
                "n2"
              ];
            };
          }
        ) true
      )).success
    );

  # Negative Test 4: Plaintext secret (`text`) or imperative hook (`preDeployHook`) must fail evaluation
  plaintextSecretRejected =
    !(
      (builtins.tryEval (
        builtins.deepSeq (epochLib.validateSecretEnvelopes {
          bad-node = {
            secrets.leaked_key = {
              text = "PLAINTEXT_SECRET_LEAK";
              owner = "root";
              group = "root";
              mode = "0400";
            };
          };
        }) true
      )).success
    );

  imperativeHookRejected =
    !(
      (builtins.tryEval (
        builtins.deepSeq (epochLib.validateSecretEnvelopes {
          hook-node = {
            preDeployHook = "rm -rf /var/lib/db";
          };
        }) true
      )).success
    );

  waveOrder = map (w: w.waveId) prodCluster.sortedWaves;

  # Regression Test 5: Force mkNodeClosure (`nixosNodeOverlayDrvPaths` and `nodeOverlayClosures`)
  nodeDrvPaths = prodCluster.nixosNodeOverlayDrvPaths;
  nodeClosures = builtins.mapAttrs (_: d: d.outPath) prodCluster.nodeOverlayClosures;
  allNodeDrvsValid = lib.all (
    n:
    lib.hasPrefix "/nix/store/" nodeDrvPaths.${n}
    && lib.hasSuffix "-epoch-node-${n}.drv" nodeDrvPaths.${n}
    && lib.hasPrefix "/nix/store/" nodeClosures.${n}
  ) (builtins.attrNames nodeDrvPaths);

  # Regression Test 6: Custom archetype setting an option outside core-base-modules.json
  # (`services.caddy.enable = true`) must fall back to full module-list.nix (`fullSys`)
  # rather than silently dropping the option under `_module.check = false`.
  emptyArchSys = epochLib.evalArchetype {
    inherit nixpkgs;
    system = "x86_64-linux";
    archName = "empty-arch";
    archModule = { };
  };
  customCaddyArchSys = epochLib.evalArchetype {
    inherit nixpkgs;
    system = "x86_64-linux";
    archName = "caddy-arch";
    archModule = {
      services.caddy.enable = true;
    };
  };
  customFallbackVerified =
    (customCaddyArchSys.config.services.caddy.enable == true)
    && (
      customCaddyArchSys.config.system.build.toplevel.drvPath
      != emptyArchSys.config.system.build.toplevel.drvPath
    );
in
assert lib.assertMsg (waveOrder == [
  "db-canary"
  "db-cohort"
  "api-fleet"
]) "Expected topological wave order [db-canary, db-cohort, api-fleet], got ${builtins.toJSON waveOrder}";
assert lib.assertMsg cycleRejected "Cyclic wave DAG must be rejected at Nix evaluation time";
assert lib.assertMsg quorumMinorityRejected "Quorum maxUnavailable > floor((|Q|-1)/2) must be rejected";
assert lib.assertMsg waveQuorumOverlapRejected "Wave exceeding quorum maxUnavailable must be rejected";
assert lib.assertMsg plaintextSecretRejected "Plaintext secret in node.secrets must be rejected at Nix evaluation time";
assert lib.assertMsg imperativeHookRejected "Imperative preDeployHook must be rejected at Nix evaluation time";
assert lib.assertMsg (
  prodCluster.p2pTree."api-1".isRackSeed && prodCluster.p2pTree."db-1".parent == "api-1"
) "Rack-a P2P tree must elect api-1 as seed and db-1 as child";
assert lib.assertMsg allNodeDrvsValid "All per-node mkNodeClosure .drv and outPath store paths must evaluate cleanly";
assert lib.assertMsg customFallbackVerified "Custom archetype outside core-base-modules.json must fall back to full module-list.nix and preserve options";
{
  status = "ALL_NIX_SCHEMA_AND_QUORUM_INVARIANTS_VERIFIED";
  inherit
    waveOrder
    cycleRejected
    quorumMinorityRejected
    waveQuorumOverlapRejected
    plaintextSecretRejected
    imperativeHookRejected
    nodeDrvPaths
    customFallbackVerified
    ;
  p2pTree = prodCluster.p2pTree;
}
