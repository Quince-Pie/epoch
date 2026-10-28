# epoch

`epoch` is a transactional fleet deployment engine and Nix flake library for NixOS.
It is a fast, memory-bounded, and split-brain-free replacement for [`deploy-rs`](https://github.com/serokell/deploy-rs) and [`colmena`](https://github.com/zhaofengli/colmena).
While it does not carry legacy SSH wrapper scripts or imperative shell hooks, it provides strict transactional guarantees across evaluation, delta transport, hardware-bound secrets, and multi-node wave activation.

[Features](#features) • [Quick start](#quick-start) • [How to use](#how-to-use) • [Benchmarks](#benchmarks) • [Building](#building) • [Command-line options](#command-line-options) • [Troubleshooting](#troubleshooting)

## Features

* **Two-tier `Archetype + /node-overlay` evaluation**: Evaluates the NixOS module fixpoint once per service archetype (`consensus-db`, `edge-api`, `cache-tier`, `worker-node`) and synthesizes per-node `/node-overlay` derivations in `~4 µs` per node.
* **[Orders-of-magnitude faster evaluation](#plane-1-cluster-evaluation-n--4-8-16-24)**: Cold `--no-eval-cache` evaluation runs in **`1.55–1.59 s`** with **`~422 MiB` peak RSS** across `N = 4..24` (**`17.5x` faster** and **`19.7x` lower RSS** than `colmena` at `N = 24`); warm `BLAKE3` Merkle-verified evaluation runs in **`90–175 µs`** with **`5.8 MiB` RSS** (**`56,297x–158,019x` faster**).
* **100% bit-for-bit NixOS `.drv` parity**: Slicing `baseModules` to the closed active 157-module core set (`nix/core-base-modules.json`, with automatic `checkDefsInOptions` fallback to full `module-list.nix`) and computing canonical `derivationStrict` `SHA-256` ATerms produces the exact same `/nix/store/*.drv` paths as upstream `nix eval`.
* **[Store-hash-normalized `FastCDC` delta transport](#plane-2-store-hash-normalized-fastcdc--rack-aware-quicmtls-p2p)**: Bijective 32-byte store-hash normalization keeps **`98.08%`** of `FastCDC` chunks identical across dependency rebuilds (compared to `0%` without normalization), shrinking a `2.0 MiB` closure upgrade to a **`49.8 KiB` `zstd -3` wire delta** (**`41.1x` smaller**).
* **Rack-aware `quinn` QUIC/mTLS 1.3 P2P tree**: Distributes missing chunks once per rack seed (`k = 4` fanout, raw Ed25519 SPKI pinning, `ALPN = "epoch-p2p/1"`), cutting coordinator egress by **`1,644.7x`** at `N = 1,000`.
* **Zero-skew secrets on unswappable `ramfs`**: Seals secrets into in-store `ChaCha20-Poly1305` + `BLAKE3`-AAD envelopes (`epoch-secrets.cbor`) bound to TPM 2.0 PCR policies or host X25519 keys, unseals into `/run/epoch/secrets/gen-<tx>` on `ramfs`, flips `/run/epoch/current-secrets` in **`~19 µs`** via `renameat2(..., RENAME_EXCHANGE)`, and zero-wipes retired generations with `explicit_bzero`.
* **Two-phase lease-fenced wave barriers (`BARRIER_WAIT`)**: Holds all nodes in a rollout wave under `CLOCK_BOOTTIME` leases until 100% of the cohort passes systemd, TCP/HTTP, `/dev/kmsg`, cgroup `oom_kill`, and peer-mesh quorum checks—or rolls the entire cohort back together in `< 350 ms`.
* **3-layer kernel & initrd panic recovery**: Combines `/dev/watchdog`, `systemd-boot` single-trial boot counting (`+1-0.conf` $\to$ `+0-1.conf`), and post-reboot `state.cbor` reconciliation with coordinator-free early-boot secret unsealing (`epoch-agent unseal-boot`).
* **Tiny, OOM-immune target daemon**: `epoch-agent` compiles to a **`3.20 MiB`** stripped binary that locks its pages in RAM via `mlockall(MCL_CURRENT | MCL_FUTURE)` and sets `OOMScoreAdjust = -1000`.

## Quick start

`epoch` models a NixOS fleet as a typed DAG of rollout waves, failure-domain quorums, shared service archetypes, and per-node overlays. Important architectural differences from `deploy-rs` and `colmena` can be found throughout [`DESIGN.md`](DESIGN.md) or by searching this document for the phrase **“unlike other deployment tools”**:

* **Unlike other deployment tools**, `epoch` never evaluates `evalModules` $N$ times for $N$ identical workers, and never leaks plaintext `deployment.keys` strings into evaluation JSON stdout.
* **Unlike other deployment tools**, `epoch` never mutates `/nix/var/nix/profiles/system`, `/run/current-system`, or `/boot/loader/loader.conf` during staging or speculative activation; closures are staged under `/nix/var/nix/gcroots/epoch-staging/tx-<tx_epoch>` after `statvfs` block and inode reservation checks.
* **Unlike other deployment tools**, `epoch` never relies on an uncoordinated per-node SSH sleep timer to disarm rollbacks; cohort peers relay signed health attestations (`PeerWitnessRelay`) so an asymmetric management-link flap never triggers a false rollback while a genuine canary failure aborts the entire wave atomically.

To evaluate the 24-node reference cluster immediately from a checkout:

```bash
> ./target/release/epoch eval --nodes 24
```

## How to use

First, to get an overview of all available command-line options, run [`epoch -h`](#command-line-options) or `epoch --help` (and `epoch-agent --help` for the target daemon).

### Evaluating a cluster

The most basic operation is evaluating a cluster definition with `epoch eval`. By default, `epoch` computes the `BLAKE3` Merkle root of all tracked Nix inputs (`flake.lock`, `nix/lib.nix`, `nix/archetype-module.nix`, `nix/core-base-modules.json`, and the cluster expression), verifies that all Tier-1 archetype `.drv` paths exist in `/nix/store`, validates static quorums and Kahn's wave DAG topological order, compiles the rack-aware P2P spanning tree, and synthesizes all $N$ canonical Nix `SHA-256` per-node `/node-overlay` `.drv` store paths in microseconds:

```bash
> epoch eval --nodes 24
{
  "tool": "epoch-cached",
  "nodes": 24,
  "archetypesEvaluated": 4,
  "archetypeCacheHits": 4,
  "quorumValid": true,
  "waveOrder": [
    "w1-db-canary",
    "w2-db-member2",
    "w3-db-member3",
    "w4-fleet"
  ],
  "wallMs": 0.175,
  "peakWorkerRssMiB": 5.93
}
```

To force a cold evaluation from scratch without the `BLAKE3` archetype cache, pass `--no-eval-cache` and control worker concurrency with `--workers`:

```bash
> epoch eval --nodes 24 --no-eval-cache --workers 4
```

### Defining a cluster in `flake.nix`

In your `flake.nix`, use `epoch.lib.mkCluster` to declare service archetypes once, bind nodes to archetypes with per-node topology and sealed secret envelopes, and specify quorum invariants and causal wave barriers:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    epoch.url = "path:./epoch";
  };

  outputs = { self, nixpkgs, epoch }: {
    epochCluster = epoch.lib.mkCluster {
      inherit nixpkgs;
      system = "x86_64-linux";
      coordinatorPublicKeys = [
        "epoch-coord-primary:ed25519:b4f9c2d1e8a706543219fedcba9876543210fedcba9876543210fedcba987654"
      ];

      # Tier 1: Evaluated once per archetype
      archetypes = {
        consensus-db = { pkgs, ... }: {
          services.etcd.enable = true;
          services.postgresql = { enable = true; package = pkgs.postgresql_16; };
          services.openssh.enable = true;
        };
        edge-api = { ... }: {
          services.nginx.enable = true;
          services.openssh.enable = true;
        };
      };

      # Tier 2: Synthesized in O(1) (~4 µs/node) without re-running evalModules
      nodes = {
        node-1 = {
          archetype = "consensus-db";
          topology = { rack = "rack-1"; zone = "zone-a"; endpoint = "10.20.0.1:9443"; };
          secrets.service_secret_key = {
            owner = "root"; group = "root"; mode = "0400";
            ciphertextEnvelope = "sealed:chacha20poly1305:node-1";
          };
          params = {
            hostName = "node-1";
            ipv4 = "10.20.0.1/24";
            machineId = "0102030405060708090a0b0c0d0e0f00";
          };
        };
      };

      # Static quorum safety: |W_k ∩ Q_r| <= maxUnavailable <= floor((|Q_r| - 1) / 2)
      rollout = {
        p2pFanout = 4;
        quorums.etcd-raft = {
          members = [ "node-1" "node-5" "node-9" ];
          maxUnavailable = 1;
        };
        waves = {
          w1-db-canary  = { nodes = [ "node-1" ]; dependsOn = [ ]; };
          w2-db-member2 = { nodes = [ "node-5" ]; dependsOn = [ "w1-db-canary" ]; };
          w3-db-member3 = { nodes = [ "node-9" ]; dependsOn = [ "w2-db-member2" ]; };
        };
      };
    };
  };
}
```

If a wave concurrently targets more members of `etcd-raft` than `maxUnavailable` permits—or if `maxUnavailable` exceeds $\lfloor (|Q|-1)/2 \rfloor$—evaluation fails immediately with `QuorumSafetyViolation` before a single byte is sent over the network.

### Sealing hardware- and host-bound secrets

Instead of uploading plaintext keys over SSH into `/run/keys`, use `epoch secret-seal` to encrypt a secret into a deterministic RFC 8949 CBOR `SecretEnvelopeBundle` (`epoch-secrets.cbor`) with `ChaCha20-Poly1305` and a `BLAKE3` Additional Authenticated Data (AAD) tag bound to `(node_id, archetype_toplevel)`:

```bash
> epoch secret-seal \
    --node-id node-1 \
    --archetype-toplevel /nix/store/6djg3xwp9gpr9k42hyqcq0s2jym8jjj5-nixos-system-epoch-archetype \
    --secret-name service_secret_key \
    --input ./secrets/db-master.key \
    --output ./epoch-secrets.cbor
```

Because the AAD binds both the target `node_id` and `archetype_toplevel`, an envelope copied to another host or replayed against a different system generation is rejected during `PREPARE` before activation begins.

### Store-hash-normalized closure chunking

When a library rebuild changes 32-character Nixbase32 store hashes inside ELF binaries and scripts, standard content-defined chunking (`FastCDC`) suffers boundary shift cascades and re-transmits the entire NAR. `epoch chunk-nar` normalizes embedded `/nix/store/<32-char>-<name>` references in place (sorting non-self references by derivation name suffix `<name>`) before running `FastCDC` (`16/64/256 KiB`) and `zstd -3`:

```bash
> epoch chunk-nar \
    --path /nix/store/6djg3xwp9gpr9k42hyqcq0s2jym8jjj5-nixos-system-epoch-archetype \
    --logical-store-path /nix/store/6djg3xwp9gpr9k42hyqcq0s2jym8jjj5-nixos-system-epoch-archetype \
    --output-manifest ./manifest.cbor
```

### Executing a transactional wave deployment

Use `epoch deploy` to execute a rollout across the wave DAG with monotonic `tx_epoch` fencing:

```bash
> epoch deploy --tx-epoch 42
```

You can also deterministically test failure recovery on the command line using fault-injection flags:

```bash
# Inject a coordinator SIGKILL after wave W1 commits while W2 is in BARRIER_WAIT:
> epoch deploy --tx-epoch 42 --inject-sigkill-on-wave W2

# Inject a Stage-1 initrd kernel panic on reboot to exercise watchdog + systemd-boot +1-0.conf fallback:
> epoch deploy --tx-epoch 43 --inject-initrd-panic

# Inject a systemd unit crash on a canary node during a coupled multi-node wave:
> epoch deploy --tx-epoch 44 --inject-unit-fail payment-engine.service
```

### Target agent & early-boot secret unsealing

On target nodes, `epoch-agent` manages `/var/lib/epoch/state.cbor`, `/run/epoch/secrets/gen-<tx>`, `/run/epoch/current-secrets`, `/dev/watchdog`, and the QUIC/mTLS listener:

```bash
# Inspect persistent state, highest_tx_epoch fencing token, and active secret generation:
> epoch-agent status

# Unseal secrets from /run/booted-system during Stage-2 early boot without coordinator contact:
> epoch-agent unseal-boot

# Run the mlockall-pinned, OOM-immune QUIC/mTLS target agent:
> epoch-agent daemon
```

### Adversarial fault-injection verification

To run all five Gate 4 adversarial fault scenarios end-to-end (coordinator `SIGKILL` mid-DAG, asymmetric management and data-plane partitions, broken kernel/initrd panic across reboot, `BLAKE3` chunk bit-flip + `/nix/store` `statvfs` `ENOSPC`, and canary unit failure in a coupled wave):

```bash
> epoch verify-fault-matrix
```

## Benchmarks

All benchmarks compare `epoch` head-to-head against [`colmena`](https://github.com/zhaofengli/colmena) (`src/nix/hive/eval.nix`, `src/nix/host/ssh.rs`, `src/nix/host/key_uploader.template.sh`) and [`deploy-rs`](https://github.com/serokell/deploy-rs) (`nix/transform-deploy.nix`, `src/cli.rs`, `src/deploy.rs`, `src/bin/activate.rs`) on identical 4-archetype NixOS clusters.

To reproduce the entire benchmark suite and write machine-readable results to [`benchmarks/results/head-to-head-results.json`](benchmarks/results/head-to-head-results.json):

```bash
> ./benchmarks/run-all.sh
```

Individual plane benchmarks can also be run directly via `./benchmarks/eval-scale.sh`, `./benchmarks/p2p-scale.sh`, and `./benchmarks/fault-and-footprint.sh`. Full methodology and Tracy `v0.14.1` zone telemetry are documented in [`benchmarks/BENCHMARK_REPORT.md`](benchmarks/BENCHMARK_REPORT.md).

### Plane 1: Cluster evaluation (`N = 4, 8, 16, 24`)

| Nodes (`N`) | Tool | Wall-Clock Latency | Peak RSS | Plaintext Secret Leaks | Speedup vs. `colmena` | RSS Reduction vs. `colmena` |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **4** | **`epoch-cached` (Warm `BLAKE3` + Native `SHA-256` ATerm)** | **`0.090 ms` (`89.8 µs`)** | **`5.80 MiB`** | **`0`** | **`56,297x`** | **`267.0x`** |
| **4** | **`epoch` (Cold `--no-eval-cache`)** | **`1,553.5 ms`** | **`422.9 MiB`** | **`0`** | **`3.25x`** | **`3.66x`** |
| **4** | `colmena` | `5,055.0 ms` | `1,549.0 MiB` | `4` | `1.00x` | `1.00x` |
| **4** | `deploy-rs` | `5,317.6 ms` | `1,530.2 MiB` | `0` | `0.95x` | `1.01x` |
| **8** | **`epoch-cached` (Warm `BLAKE3` + Native `SHA-256` ATerm)** | **`0.106 ms` (`106.4 µs`)** | **`5.85 MiB`** | **`0`** | **`96,306x`** | **`488.6x`** |
| **8** | **`epoch` (Cold `--no-eval-cache`)** | **`1,592.1 ms`** | **`424.0 MiB`** | **`0`** | **`6.44x`** | **`6.74x`** |
| **8** | `colmena` | `10,249.0 ms` | `2,859.3 MiB` | `8` | `1.00x` | `1.00x` |
| **8** | `deploy-rs` | `9,673.8 ms` | `2,915.2 MiB` | `0` | `1.06x` | `0.98x` |
| **16** | **`epoch-cached` (Warm `BLAKE3` + Native `SHA-256` ATerm)** | **`0.151 ms` (`150.5 µs`)** | **`5.90 MiB`** | **`0`** | **`123,586x`** | **`932.6x`** |
| **16** | **`epoch` (Cold `--no-eval-cache`)** | **`1,565.2 ms`** | **`425.2 MiB`** | **`0`** | **`11.89x`** | **`12.94x`** |
| **16** | `colmena` | `18,604.2 ms` | `5,500.9 MiB` | `16` | `1.00x` | `1.00x` |
| **16** | `deploy-rs` | `18,189.1 ms` | `5,706.1 MiB` | `0` | `1.02x` | `0.96x` |
| **24** | **`epoch-cached` (Warm `BLAKE3` + Native `SHA-256` ATerm)** | **`0.175 ms` (`175.4 µs`)** | **`5.93 MiB`** | **`0`** | **`158,019x`** | **`1,405.8x`** |
| **24** | **`epoch` (Cold `--no-eval-cache`)** | **`1,580.5 ms`** | **`422.4 MiB`** | **`0`** | **`17.53x`** | **`19.72x`** |
| **24** | `colmena` | `27,710.8 ms` | `8,329.0 MiB` | `24` | `1.00x` | `1.00x` |
| **24** | `deploy-rs` | `26,882.7 ms` | `8,083.4 MiB` | `0` | `1.03x` | `1.03x` |

Across `N = 10..1,000` nodes, `epoch`'s pre-forked Copy-on-Write (`fork()`) worker pool + `BLAKE3` `EvalCache` evaluates **1,000 nodes** cold in **`34.15 ms`** (`10.57 MiB` coordinator RSS, `8.21 MiB` peak worker RSS, `16` worker `_exit(0)` recycles) and evaluates a 1-node incremental change across 1,000 nodes in **`3.31 ms`** (`999 / 1,000` cache hits, **`10.32x` warm speedup**).

### Plane 2: Store-hash-normalized `FastCDC` & rack-aware QUIC/mTLS P2P

On a `2.00 MiB` (`2,097,600 B`) NAR closure upgrade where rebuilt dependencies rewrite **512 `/nix/store/<32-char>` references** alongside a `4 KiB` binary patch, un-normalized `FastCDC` reuses **`0 / 53` chunks (`0.0%`)**, whereas `epoch` reuses **`51 / 52` chunks (`98.08%`)** and transfers only **`51,015 B` (`49.82 KiB`)** compressed (`41.12x` single-link reduction):

| Fleet Size (`N`) | Racks (`R`) | `deploy-rs` / `colmena` Coord Egress | **`epoch` Coord Egress (Rack Seeds)** | **Coord Egress Reduction** | Incumbent Transfer (`1 Gbps`) | **`epoch` P2P Transfer** | **Transfer Speedup** |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **10** | 10 | `20.98 MB` | **`510.2 KB`** | **`41.1x`** | `168.20 ms` | **`4.58 ms`** | **`36.7x`** |
| **50** | 25 | `104.88 MB` | **`1.28 MB`** | **`82.2x`** | `840.99 ms` | **`12.84 ms`** | **`65.5x`** |
| **100** | 25 | `209.76 MB` | **`1.28 MB`** | **`164.5x`** | `1,681.98 ms` | **`12.84 ms`** | **`131.0x`** |
| **500** | 25 | `1,048.80 MB` | **`1.28 MB`** | **`822.3x`** | `8,409.91 ms` | **`14.97 ms`** | **`561.9x`** |
| **1,000** | 25 | `2,097.60 MB` | **`1.28 MB`** | **`1,644.7x`** | `16,819.82 ms` | **`17.10 ms`** | **`983.6x`** |

### Planes 3 & 4: Secret swap skew & Gate 4 fault matrix

Tested across `50` consecutive secret rotations + failed activation rollback against a high-frequency reader thread (`257,309` concurrent reads):

| Invariant / Metric | `colmena` (`key_uploader.template.sh`) | `deploy-rs` (`activate-rs`) | **`epoch` (`epoch-agent`)** |
| :--- | :---: | :---: | :---: |
| **Pre-Activation Secret Skew Rate** | `100.0%` (`20 / 20` windows) | N/A (no secret primitive) | **`0.0%` (`0 / 257,309` reads)** |
| **Post-Abort Secret Corruption** | `100%` (leaves `G_{N+1}` keys live) | N/A | **`0%` (reverts to `G_N` & zero-wipes `G_{N+1}`)** |
| **Unattended Reboot Secret Survival** | `false` (`tmpfs` `/run/keys` wiped) | N/A | **`true` (`epoch-agent unseal-boot`)** |
| **Mean Atomic Secret Swap Latency** | `~2,100 µs` (shell `mv` loop) | N/A | **`19.42 µs` (`RENAME_EXCHANGE`)** |
| **Gate 4 Fault Scenarios (`Gate-4.1..4.5`)** | Fails all 5 (split-brain / key skew) | Fails all 5 (split-brain / bricked boot) | **Passes all 5 (`0` split-brain, `0` skew)** |

## Building

`epoch` is written in Rust (2024 edition) and packaged as a hermetic Nix flake.

### Building with Nix

```bash
# Build the release binaries via Nix:
> nix build

# Or enter the hermetic development shell and build with Cargo:
> nix develop --command cargo build --release --offline

# Run the complete Rust integration & Gate 4 fault-injection test suite (21 tests):
> nix develop --command cargo test --release --offline

# Run the pure-Nix schema, quorum safety, and custom-option fallback test suite:
> nix eval --impure --file nix/tests/schema-eval-test.nix
```

### Profiling with Tracy (`v0.14.1`)

`epoch` includes zero-cost C ABI bindings (`src/tracy_prof.rs`) for [`tracy-flake`](https://github.com/Quince-Pie/tracy-flake) (`v0.14.1`). When compiled without `--features tracy` (the default), all `tracy_zone!`, `tracy_frame!`, and `tracy_plot!` macros compile down to zero instructions.

```bash
> nix develop --command cargo build --release --features tracy --offline
> tracy-capture -o plane1_eval_native.tracy -f &
> EPOCH_TRACY_WAIT=1 ./target/release/epoch eval --nodes 24
> tracy-csvexport -e plane1_eval_native.tracy
```

### Dependencies

Building and running `epoch` requires:

* **Linux (`x86_64-linux` or `aarch64-linux`)** with kernel support for `renameat2(..., RENAME_EXCHANGE)`, `ramfs`, `CLOCK_BOOTTIME`, `/dev/kmsg`, cgroup v2 `memory.events`, and `/dev/watchdog`.
* **Nix (`2.18+`)** with `nix-command` and `flakes` enabled (used by the coordinator for Tier-1 archetype evaluation).
* **SQLite (`libsqlite3`)** and **`zstd` (`libzstd`)** (linked automatically by `flake.nix` and `build.rs`).

## Command-line options

### `epoch` (Coordinator CLI)

```text
Usage: epoch <COMMAND>

Commands:
  eval                 Evaluate a NixOS cluster using EPOCH's native Data-Oriented Plane 1 engine
  deploy               Execute a transactional wave DAG deployment (supports fault-injection flags)
  secret-seal          Seal a secret file into a hardware/host-bound `epoch-secrets.cbor` envelope
  chunk-nar            Serialize, normalize 32-byte store hashes, FastCDC-chunk, and zstd-compress a store path
  verify-fault-matrix  Run the complete 5-scenario Gate 4 Adversarial Fault-Injection Verification Matrix
  benchmark-eval       Run the Plane 1 Two-Tier Archetype + CoW Worker Pool + BLAKE3 EvalCache benchmark
  benchmark-p2p        Run the Plane 2 Store-Hash-Normalized FastCDC + Rack-Aware k-ary P2P Tree benchmark
  benchmark-plane34    Run the Plane 3 & 4 Target Footprint, Secret Swap Skew, and Gate 4 Fault Comparison
  benchmark-all        Run the complete Plane 1-4 Head-to-Head Benchmark Suite (`epoch` vs `deploy-rs` vs `colmena`)
```

### `epoch-agent` (Target Daemon)

```text
Usage: epoch-agent [OPTIONS] <COMMAND>

Commands:
  status                       Print current persistent agent phase, highest_tx_epoch, and secret symlink status
  unseal-boot                  Stage-2 early-boot coordinator-free secret unsealing from /run/booted-system
  debug-set-quota-reserve-mib  Override the statvfs free-space reserve in MiB for deterministic ENOSPC testing
  daemon                       Pin process memory (`mlockall`, `OOMScoreAdjust=-1000`) and run the QUIC mTLS agent

Options:
      --root <ROOT>  Target filesystem root [default: /]
```

## Troubleshooting

### `QuorumSafetyViolation` during `epoch eval`

`epoch` enforces $\forall W_k, \forall Q_r : |W_k \cap Q_r| \le \text{maxUnavailable}(Q_r) \le \lfloor (|Q_r| - 1) / 2 \rfloor$. If a single rollout wave includes multiple members of the same consensus quorum (such as a 3-node `etcd` or `postgresql` cluster with `maxUnavailable = 1`), split those nodes into sequential waves connected via `dependsOn`.

### `DisqualifiedPlaintextSecretInStore` during `epoch eval`

`epoch` rejects any secret definition that lacks a `ciphertextEnvelope` or embeds a raw plaintext marker (`PLAINTEXT_SECRET_LEAK`). Seal the secret with `epoch secret-seal` first and reference the resulting `ciphertextEnvelope`.

### `StaleEpochFenced` on target nodes

Each target persists the highest transaction epoch it has observed (`highest_tx_epoch`) in `/var/lib/epoch/state.cbor` protected by a keyed `BLAKE3` MAC. If a previous deployment was aborted at `--tx-epoch 42`, pass a strictly higher `--tx-epoch` (e.g., `--tx-epoch 43`) on the next rollout.

### `tracy-capture` hangs when profiling sub-millisecond `epoch eval`

Warm `epoch eval --nodes 24` finishes in `~175 µs`, which can exit before `tracy-capture` completes its TCP handshake on port `8086`. Set `EPOCH_TRACY_WAIT=1` when running `epoch` under `tracy-capture` so the process waits for the collector handshake and flushes all zone ringbuffers before exiting.
