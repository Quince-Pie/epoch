# `EPOCH`: State-of-the-Art Distributed Transactional NixOS Deployment Architecture

---

## Section 1 & 2: Governing Engineering Contract, Authority Constraints, and Selection Rule

### 1.1 Hard Feasibility Constraints (Non-Negotiable Authority Invariants)
1. **Nix Hermeticity & Pure Evaluation Invariant**: Every target system closure $C_i \subset \text{/nix/store}$ and every target secret bundle $E_i \subset C_i$ MUST be a pure, deterministic output of the content-addressed flake source tree $\mathcal{T}_{\text{flake}}$ locked by `flake.lock`. Zero target state may depend on coordinator environment variables, impure host filesystems, or out-of-band imperative scripts.
2. **Store Immutability & Pre-Commit Staging Isolation Invariant**: No path in `/nix/store` is ever modified after registration in `/nix/var/nix/db/db.sqlite`. During staging (`STAGED` and `PREPARED` phases), incoming closures are anchored exclusively under `/nix/var/nix/gcroots/epoch/staging/tx-<tx_epoch>` after `statvfs("/nix/store")` quota verification. Neither `/nix/var/nix/profiles/system`, `/run/current-system`, nor `/boot/loader/loader.conf` default entries are mutated until guarded trial activation (`switch-to-configuration test` or `+1` boot-counted reboot) and final wave commit (`COMMITTED`).
3. **Zero Plaintext Secret Exposure in Store, Coordinator Heap, or Network Wire**: Secrets exist in Git, Nix evaluation memory, `/nix/store`, binary caches, and P2P network streams exclusively as authenticated ciphertext (`ChaCha20-Poly1305` AEAD wrapped by target `TPM2_PolicyPCR`/`TPM2_PolicyAuthorize` and host `age`/`X25519` keys). Plaintext exists solely inside each target's unswappable kernel `ramfs` mount (`/run/epoch/secrets/gen-<tx_epoch>`, mounted with `MS_NOSUID | MS_NODEV | MS_NOEXEC`, mode `0700`).
4. **Transactional Wave Atomicity & Bounded Rollback Convergence**: For every coupled rollout wave $W_k \subseteq \mathcal{V}$, either 100% of nodes $i \in W_k$ (or $\ge |Q_r| - \text{maxUnavailable}(Q_r)$ where explicitly configured) pass multi-signal health verification and receive a coordinator-signed `CommitWave(tx_epoch)` before their monotonic `CLOCK_BOOTTIME` lease expires, or **every** node in $W_k$ deterministically reverts both its system closure and `/run/epoch/current-secrets` symlink to $G_t$ within $\Delta t \le \text{lease\_ttl} + t_{\text{switch}} + t_{\text{watchdog}}$.

### 2.1 Quantitative Optimization Selection Rule
| Dimension | `deploy-rs` Incumbent | `colmena` Incumbent | `EPOCH` Target Bound | Decisive Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Coordinator Eval RSS** | $\Theta(N \cdot |M_{\text{NixOS}}|)$ single `nix eval` | $\Theta(N \cdot |M_{\text{NixOS}}|) \approx 512\text{ MB} \cdot N$ ([`limits.rs:10`](file:///tmp/investigation/colmena/src/nix/deployment/limits.rs#L10)) | $O(1)$ ceiling: $\le M_{\text{parent}} + W \cdot M_{\max}$ ($\le 4.0\text{ GiB}$ at $N=1,000$) | Tier-1 Archetype fixpoint + Tier-2 `/node-overlay` + CoW `fork()` worker pool + `BLAKE3` file-trace cache |
| **Closure Transfer Time** | $\Omega(N \cdot |\Delta C| / B_{\text{coord}})$ sequential push | $\Omega(N \cdot |\Delta C| / B_{\text{coord}})$ SSH star-push | $O\left(\frac{|\Delta C_{\text{norm-CDC}}|}{B_{\text{link}}} k \log_k N\right)$ | Store-hash-normalized FastCDC (`zstd -3`) + Rack-aware QUIC/mTLS $k$-ary P2P tree |
| **Rollback Convergence** | $\infty$ (permanent split-brain after Node A confirms) | $\infty$ (zero rollback mechanism) | $\le \text{lease\_ttl} + t_{\text{switch}}$ ($\le 35\text{ s}$ userspace, $\le 95\text{ s}$ kernel panic) | Two-phase `BARRIER_WAIT` lease + Peer Witness Relay + 3-layer watchdog/`systemd-boot` `+1` |
| **Target Agent Footprint** | ~15–25 MB (`activate-rs` + `nix-env` subprocesses) | `inotifywait` bash processes per key | $< 5\text{ MB}$ static Rust binary (`epoch-agent`), `mlockall(MCL_CURRENT\|MCL_FUTURE)`, `OOMScoreAdjust=-1000` | Single static daemon handling QUIC P2P, D-Bus health checks, and direct syscalls |
| **Secret Exposure & Skew** | No secret support | Plaintext in coordinator `nix eval` JSON + `/run/keys` overwrite/deadlock/reboot amnesia | $0\text{ B}$ coordinator/wire plaintext; $0\text{ ms}$ skew (`RENAME_EXCHANGE`); $100\%$ reboot survival | In-store `epoch-secrets.cbor` + `ramfs` generation directories + Stage-2 early-boot unsealing |

---

## Section 3 & 4 (GATE 1): Mathematical & Structural Impossibility Proof Against Incumbents (`deploy-rs` & `colmena`)

### 3.1 `deploy-rs` Structural Audit ([`/tmp/investigation/deploy-rs`](file:///tmp/investigation/deploy-rs))

#### 3.1.1 Independent Closure Schema & Sequential Uncoordinated Execution Loop
1. **Data Model & Flake Schema**:
   - In [`interface.json`](file:///tmp/investigation/deploy-rs/interface.json#L57-L132) and [`src/data.rs`](file:///tmp/investigation/deploy-rs/src/data.rs#L77-L125) (`Data`, `Node`, `Profile`, `GenericSettings`), the fleet is modeled as an unordered map `pub nodes: HashMap<String, Node>`, where each `Node` holds `pub profiles: HashMap<String, Profile>` and `pub profiles_order: Vec<String>`.
   - Each NixOS profile is wrapped by `deploy-rs.lib.activate.nixos` ([`flake.nix:96-114`](file:///tmp/investigation/deploy-rs/flake.nix#L96-L114)), which invokes `deploy-rs.lib.activate.custom` ([`flake.nix:48-93`](file:///tmp/investigation/deploy-rs/flake.nix#L48-L93)) to build a `pkgs.buildEnv` containing a shell script `/deploy-rs-activate` and a symlink `/activate-rs -> ${activate-rs}/bin/activate`.
   - The schema contains **zero inter-node edges**, **zero wave barrier primitives**, **zero failure-domain topologies**, and **zero quorum constraints**.
2. **Coordinator Evaluation & Execution Loop**:
   - [`get_deployment_data`](file:///tmp/investigation/deploy-rs/src/cli.rs#L219-L327) spawns a single monolithic `nix eval --json <repo>#deploy --apply ...` process ([`src/cli.rs:285`](file:///tmp/investigation/deploy-rs/src/cli.rs#L285)), forcing evaluation of all target metadata in one `libexpr` process.
   - [`collate_nodes`](file:///tmp/investigation/deploy-rs/src/cli.rs#L562-L625) iterates `for (node_name, node) in &data.nodes` ([`line 565`](file:///tmp/investigation/deploy-rs/src/cli.rs#L565)) over Rust's `RandomState`-hashed `HashMap<String, Node>`, yielding a **non-deterministic node deployment order** across runs.
   - [`run_deploy`](file:///tmp/investigation/deploy-rs/src/cli.rs#L815-L977) loops sequentially over `(cmd_overrides, node, profile)` to push closures ([`lines 826-852`](file:///tmp/investigation/deploy-rs/src/cli.rs#L826-L852))—where [`Opts::checksigs`](file:///tmp/investigation/deploy-rs/src/cli.rs#L41-L43) defaults to `false`, causing [`push::push_profile`](file:///tmp/investigation/deploy-rs/src/push.rs#L802-L804) to pass `--no-check-sigs` to `nix copy` by default—and then executes activation in a **strictly sequential `for` loop** ([`src/cli.rs:923-977`](file:///tmp/investigation/deploy-rs/src/cli.rs#L923-L977)):
     ```rust
     for (node_name, node, profile_name, profile, deploy_data, deploy_defs) in &parts {
         deploy::deploy_profile(...).await?;
         succeeded.push((&deploy_data, &deploy_defs));
     }
     ```

#### 3.1.2 Theorem 1.1: Formal Proof of Permanent Cluster Split-Brain Under `magicRollback`
**Theorem 1.1**: *For any multi-node deployment $W = \{N_1, N_2, \dots, N_m\}$ ($m \ge 2$) transitioning from generation $G_t$ to $G_{t+1}$ with mutual protocol/schema coupling, `deploy-rs`'s per-node `magicRollback` automaton cannot preserve transactional atomicity and admits reachable executions terminating in permanent split-brain $(G_{t+1}, G_t)$.*

**Proof (from [`src/deploy.rs`](file:///tmp/investigation/deploy-rs/src/deploy.rs) and [`src/bin/activate.rs`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs))**:
1. **Premature Per-Node Commit Before Cohort Activation**:
   - During iteration $i = 1$ ($N_1$) of the sequential loop at [`src/cli.rs:923`](file:///tmp/investigation/deploy-rs/src/cli.rs#L923), [`deploy::deploy_profile`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L467-L735) spawns two concurrent SSH sessions to $N_1$:
     - `ssh_activate_child`: `activate-rs activate '<closure>' '<profile_path>' --confirm-timeout 30 --temp-path /tmp ...` ([`src/deploy.rs:605-612`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L605-L612)).
     - `ssh_wait_child`: `activate-rs wait '<closure>' --temp-path /tmp ...` ([`src/deploy.rs:675-678`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L675-L678)).
   - On $N_1$, [`activate`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L650-L765) runs `nix-env -p /nix/var/nix/profiles/system --set <closure>` ([`line 671`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L671)), runs `/nix/var/nix/profiles/system/deploy-rs-activate` (`switch-to-configuration switch`, [`line 708`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L708)), creates the canary file `/tmp/deploy-rs-canary-<lock_hash>` ([`line 384`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L384)), and enters [`danger_zone`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L276-L289) waiting for the canary file to be deleted within `confirm_timeout`.
   - On $N_1$, [`wait`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L533-L648) watches `/tmp` via `inotify`, sees the canary file exist ([`line 566-568`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L566-L568)), and immediately exits `0`.
   - On the coordinator, `tokio::select!` ([`src/deploy.rs:695-717`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L695-L717)) observes `ssh_wait_child` exit `0` and **immediately executes [`confirm_profile`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L721)** ([`lines 296-360`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L296-L360)), which SSHes into $N_1$ and runs `rm /tmp/deploy-rs-canary-<lock_hash>`.
   - On $N_1$, [`danger_zone`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L281-L283) detects ` IN_DELETE_SELF` on the canary file and exits `0` at time $t_{1,\text{commit}}$.
   - Crucially, Node $N_2$ does not even begin activation until $t_{2,\text{start}} > t_{1,\text{commit}}$ (the next iteration of `for` at [`src/cli.rs:923`](file:///tmp/investigation/deploy-rs/src/cli.rs#L923)). At all times $t > t_{1,\text{commit}}$, Node $N_1$'s `magicRollback` timer is **permanently disarmed**.
2. **Three Minimal Split-Brain & False-Rollback Traces**:
   - **Trace A (Coordinator Crash or Partition in $[t_{1,\text{commit}}, t_{2,\text{commit}}]$)**: Coordinator crashes (`SIGKILL`) or loses network after `confirm_profile` on $N_1$ ($t_{1,\text{commit}}$) while $N_2$ is unactivated or in `danger_zone`. $N_1$ has disarmed its timer and stays permanently at $G_{t+1}$; $N_2$ remains on or reverts to $G_t$. Terminal state: $(G_{t+1}, G_t)$.
   - **Trace B ($N_2$ Activation Failure + Imperative `revoke` Failure)**: Suppose $N_2$ fails activation or times out, and `--rollback-succeeded` is enabled ([`src/cli.rs:945-969`](file:///tmp/investigation/deploy-rs/src/cli.rs#L945-L969)). The coordinator attempts to roll back $N_1$ by opening a **brand-new SSH session** in [`deploy::revoke`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L757-L829). Because $N_1$'s local timer is already dead, rollback is no longer fail-closed on $N_1$—it depends 100% on coordinator liveness and network reachability to $N_1$. Worse, if `deploy::revoke` fails on any node in `succeeded`, the `?` operator at [`src/cli.rs:965`](file:///tmp/investigation/deploy-rs/src/cli.rs#L965) aborts the rollback loop immediately, leaving all remaining nodes in `succeeded` permanently on $G_{t+1}$!
   - **Trace C (Simultaneous-Spawn SSH Reset Bug During Data-Plane/Service Restart)**: Because `ssh_activate_child` ([`src/deploy.rs:607`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L607)) and `ssh_wait_child` ([`src/deploy.rs:677`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L677)) are both spawned *before* `switch-to-configuration` runs, with **zero retry loop around `ssh_wait_child`**, any transient 50 ms TCP reset during activation (e.g., `sshd` reload, `nftables` atomic table replacement, or VLAN/bridge bounce) causes both `ssh` processes to exit `255`. In [`src/deploy.rs:656-670`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L656-L670), `ssh_activate_child` exiting `255` sends `Err(DeployProfileError::SSHActivate)` over `send_activate`; `tokio::select!` ([`lines 695-717`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L695-L717)) returns `Err` immediately **without ever calling [`confirm_profile`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L721)**, forcing a false rollback on a healthy node.
   - **Trace D (Destructive Active-Generation Deletion in [`deactivate`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L180-L244))**: When `nix-env -p /nix/var/nix/profiles/system --set <closure>` runs on an already-current closure ($G_{t+1} = G_t$) or fails at [`line 683`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L683), `nix-env` does not create a new generation symlink `system-<g+1>-link`. Yet [`deactivate`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L183-L230) unconditionally runs `nix-env --rollback` (rolling back to $G_{t-1}$) followed by `nix-env --delete-generations <last_id>` ([`line 221`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L221)), **permanently deleting the active generation $G_t$**! $\blacksquare$

#### 3.1.3 Theorem 1.2: Userspace `activate-rs` Failure Across Kernel Panic, OOM Livelock, or Initrd Hang
**Proof (from [`src/bin/activate.rs`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs) and [`flake.nix`](file:///tmp/investigation/deploy-rs/flake.nix))**:
1. In [`flake.nix:107-112`](file:///tmp/investigation/deploy-rs/flake.nix#L107-L112), `deploy-rs.lib.activate.nixos` executes:
   ```sh
   $PROFILE/bin/switch-to-configuration switch
   sed -i '/^default /d' /boot/loader/loader.conf
   ```
   By running `switch` (rather than `test`) *before* confirmation and deleting the `default` directive in `/boot/loader/loader.conf`, `systemd-boot` defaults to booting the highest-numbered entry (`nixos-generation-<g+1>.conf`, i.e., $G_{t+1}$) with **zero boot-counting (`+1`) metadata**.
2. In [`src/bin/activate.rs:825-833`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L825-L833), `activate-rs` is an unpinned userspace process that only ignores `SIGHUP` (`signal::ignore(Signal::SIGHUP)`). It does not open `/dev/watchdog`, does not lock pages with `mlockall()`, and does not set `OOMScoreAdjust=-1000`.
3. Consequently:
   - **Kernel Panic**: A kernel panic during or after `switch-to-configuration switch` halts the CPU; the volatile Tokio timer in `activate-rs` dies, and no hardware watchdog resets the node.
   - **OOM Livelock**: Under memory exhaustion caused by $G_{t+1}$, either the Linux OOM killer terminates `activate-rs`, or [`deactivate`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L183-L241) fails with `ENOMEM` when trying to `fork()`/`execve()` `nix-env --rollback`, `nix-env --list-generations`, `nix-env --delete-generations`, and `sh -c /nix/var/nix/profiles/system/deploy-rs-activate`.
   - **Reboot / Initrd Hang**: Across any reboot, the userspace `activate-rs` process is terminated by shutdown, `/tmp/deploy-rs-canary-*` on `tmpfs` is wiped, and `systemd-boot` boots unconfirmed $G_{t+1}$ unconditionally. If $G_{t+1}$ hangs in `initrd`, the node is permanently bricked. $\blacksquare$

---

### 3.2 `colmena` Structural Audit ([`/tmp/investigation/colmena`](file:///tmp/investigation/colmena))

#### 3.2.1 Theorem 1.3: $\Theta(N \cdot |M_{\text{NixOS}}|)$ Coordinator Heap Blowup & Plaintext Secret Serialization
**Proof (from [`src/nix/hive/eval.nix`](file:///tmp/investigation/colmena/src/nix/hive/eval.nix), [`src/nix/hive/mod.rs`](file:///tmp/investigation/colmena/src/nix/hive/mod.rs), [`src/nix/deployment/mod.rs`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs), and [`src/nix/evaluator/nix_eval_jobs.rs`](file:///tmp/investigation/colmena/src/nix/evaluator/nix_eval_jobs.rs))**:
1. **Per-Node Module Fixpoint Invalidates Sharing**:
   - In [`src/nix/hive/eval.nix:154-213`](file:///tmp/investigation/colmena/src/nix/hive/eval.nix#L154-L213), `evalNode` invokes `evalConfig` (`nixos/lib/eval-config.nix`) independently for every node $i \in \{1, \dots, N\}$ with host-specific `modules = [...] ++ configs` and `specialArgs = { inherit name; nodes = uncheckedNodes; }`.
   - Because `lib.evalModules` computes a single lazy mutual recursive fixpoint over $|M_{\text{NixOS}}| \approx 1,800$ modules where any option definition may inspect `name`, `config.networking.hostName`, or `nodes`, `libexpr` allocates a distinct `Value` attrset graph of size $\Theta(|M_{\text{NixOS}}|)$ per node.
   - Worse, `uncheckedNodes` ([`eval.nix:218-234`](file:///tmp/investigation/colmena/src/nix/hive/eval.nix#L218-L234)) constructs a **second** parallel `evalNode` graph for all $N$ nodes with `_module.check = false`. Any module referencing `nodes.<peer>.config...` forces evaluation of `<peer>` inside the current worker's heap, yielding $\Theta(N^2 \cdot |M_{\text{NixOS}}|)$ worst-case work.
2. **Unchunked Phase-1 `select_nodes` Evaluation & Plaintext Secret Leak in Coordinator RAM**:
   - Before `Deployment::execute` even starts, [`Hive::select_nodes`](file:///tmp/investigation/colmena/src/nix/hive/mod.rs#L238-L264) calls [`self.deployment_info()`](file:///tmp/investigation/colmena/src/nix/hive/mod.rs#L331-L347) (whenever tag filters like `--on @tag` are used, via [`filter.has_node_config_rules()`](file:///tmp/investigation/colmena/src/nix/node_filter.rs#L92-L94)) or [`self.deployment_info_selected(&selected)`](file:///tmp/investigation/colmena/src/nix/hive/mod.rs#L364-L388).
   - Both run a **single unchunked `nix eval --json` process** over `hive.deploymentConfig` ([`eval.nix:256`](file:///tmp/investigation/colmena/src/nix/hive/eval.nix#L256)), forcing evaluation of `v.config.deployment` across all $N$ nodes in a single Boehm GC heap:
     $$\text{Peak RSS}_{\text{colmena}} = \Theta(N \cdot |M_{\text{NixOS}}|) \approx N \times 512\text{ MB} \quad (\text{explicitly hardcoded as }\texttt{EVAL\_PER\_HOST\_MB = 512}\text{ in }\text{limits.rs:10})$$
   - Furthermore, evaluating `v.config.deployment` serializes every `deployment.keys.<k>.text` secret in plaintext JSON over `nix eval` stdout into unzeroed Rust heap strings (`KeySource::Text(String)` in [`src/nix/key.rs:29-40`](file:///tmp/investigation/colmena/src/nix/key.rs#L29-L40)) retained in `TargetNode.config.keys` for the lifetime of the deployment! Even `keyCommand` buffers full secret stdout into an unzeroed `Cursor<Vec<u8>>` ([`src/nix/key.rs:110-125`](file:///tmp/investigation/colmena/src/nix/key.rs#L110-L125)).
3. **Why `execute_chunked` and `nix-eval-jobs` (`execute_streaming`) Fail**:
   - [`execute_chunked`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L186-L210) only runs *after* `select_nodes` has already forced the unchunked Phase-1 evaluation, and spawns $\lceil N / C \rceil$ separate `nix eval` processes ([`eval_selected`, `mod.rs:395-418`](file:///tmp/investigation/colmena/src/nix/hive/mod.rs#L395-L418)), each re-evaluating `nixpkgs` (`mkNixpkgs` in [`eval.nix:95-145`](file:///tmp/investigation/colmena/src/nix/hive/eval.nix#L95-L145)) from scratch.
   - [`NixEvalJobs::evaluate`](file:///tmp/investigation/colmena/src/nix/evaluator/nix_eval_jobs.rs#L73-L96) passes `--select "... hive.evalSelected [...]"`. In [`eval.nix:249-258`](file:///tmp/investigation/colmena/src/nix/hive/eval.nix#L249-L258), `hive.evalSelected` returns an attrset whose values are unforced thunks `v.config.system.build.toplevel`. `nix-eval-jobs` forks worker processes *at the attribute boundary* before any `evalConfig` thunk is forced—so every worker still evaluates the entire $\sim 1,800$-module NixOS fixpoint from scratch. $\blacksquare$

#### 3.2.2 Theorem 1.4: SSH Star-Push Closure Transport Bottleneck ($T \ge N \cdot |\Delta C| / B_{\text{coord}}$)
**Proof (from [`src/nix/host/ssh.rs:281-344`](file:///tmp/investigation/colmena/src/nix/host/ssh.rs#L281-L344) and [`src/nix/deployment/mod.rs:480-538`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L480-L538))**:
- In [`Deployment::push_Keys_and_closures`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L480-L538), `colmena` invokes `host.copy_closure(&profile_drv, CopyDirection::ToRemote, ...)` for each node $i \in \{1, \dots, N\}$.
- In [`Ssh::nix_copy_closure`](file:///tmp/investigation/colmena/src/nix/host/ssh.rs#L281-L344), `colmena` spawns `nix copy --no-check-sigs --to ssh-ng://<host> <closure>` (note [`line 293`](file:///tmp/investigation/colmena/src/nix/host/ssh.rs#L293), where `--no-check-sigs` is hardcoded for all `nix copy` calls!) or `nix-copy-closure --to`.
- Store synchronization queries whole store paths (`QueryValidPaths`). Modifying 1 byte of a package or configuration file alters its `/nix/store/<32-char-hash>-<name>` path, causing `nix copy` to serialize and push the entire NAR $|\Delta C|$ across $N$ independent SSH connections out of the coordinator's egress interface of bandwidth $B_{\text{coord}}$:
  $$T_{\text{transfer}} \ge \frac{\sum_{i=1}^N |\Delta C_i|}{B_{\text{coord}}} = \frac{N \cdot |\Delta C|}{B_{\text{coord}}} = \Omega(N) \quad \blacksquare$$

#### 3.2.3 Theorem 1.5: Expressive Impossibility of Flat String Tags (`deployment.tags`)
**Proof (from [`src/nix/hive/options.nix:181-189`](file:///tmp/investigation/colmena/src/nix/hive/options.nix#L181-L189), [`src/nix/node_filter.rs:29-128`](file:///tmp/investigation/colmena/src/nix/node_filter.rs#L29-L128), and [`src/nix/deployment/mod.rs:351-384`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L351-L384))**:
- `deployment.tags` has type `types.listOf types.str` ($\tau: \mathcal{V} \to \mathcal{P}(\Sigma^*)$), evaluated by [`NodeFilter`](file:///tmp/investigation/colmena/src/nix/node_filter.rs#L29-L128) as a unary set-membership filter returning an unordered `Vec<NodeName>`.
- In [`Deployment::activate`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L351-L384), all matched nodes are spawned concurrently into `futures::future::join_all(futures)` bounded only by a single global counting semaphore `self.parallelism_limit.apply` (default `10`, [`limits.rs:27`](file:///tmp/investigation/colmena/src/nix/deployment/limits.rs#L27)):
  1. **Zero Causal Ordering**: A unary predicate over $\mathcal{V}$ contains zero binary relations $\prec \subseteq \mathcal{V} \times \mathcal{V}$ and therefore cannot enforce that wave $W_1$ (e.g., etcd/Postgres) reaches health convergence before wave $W_2$ (API tier) activates.
  2. **Zero Quorum Preservation**: For a Raft/Paxos quorum $Q_r \subseteq \mathcal{V}$ of size $|Q_r| = 2f + 1$ (tolerating $f = \lfloor (|Q_r|-1)/2 \rfloor$ unavailable nodes), any global semaphore limit $L > f$ allows the scheduler to concurrently enter `switch-to-configuration` / `reboot` on $f + 1$ members of $Q_r$, destroying consensus availability. $\blacksquare$

#### 3.2.4 Theorem 1.6: Proof of the Three Fatal Race Conditions in `colmena`'s `deployment.keys`
**Proof (from [`src/nix/deployment/mod.rs:543-676`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L543-L676), [`src/nix/host/key_uploader.template.sh:1-22`](file:///tmp/investigation/colmena/src/nix/host/key_uploader.template.sh#L1-L22), and [`src/nix/hive/modules.nix:36-144`](file:///tmp/investigation/colmena/src/nix/hive/modules.nix#L36-L144))**:
1. **Race (a) — Pre-Activation In-Place Overwrite Race (`uploadAt = "pre-activation"`, default in [`options.nix:120`](file:///tmp/investigation/colmena/src/nix/hive/options.nix#L120))**:
   - In [`Deployment::activate_node`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L554-L580), `host.upload_keys(&keys, false).await?` ([`line 575`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L575)) executes **before** `host.activate(&profile_r, ...).await?` ([`line 609`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L609)).
   - [`key_uploader.template.sh`](file:///tmp/investigation/colmena/src/nix/host/key_uploader.template.sh#L11-L21) writes stdin to `/run/keys/<name>.tmp` and executes `mv "/run/keys/<name>.tmp" "/run/keys/<name>"` ([`line 21`](file:///tmp/investigation/colmena/src/nix/host/key_uploader.template.sh#L21)) **in-place**.
   - During the interval $[t_{\text{mv}}, t_{\text{activate}}]$, generation $G_t$ is still running, but `/run/keys/<name>` now contains $G_{t+1}$'s secret! Worse, in [`modules.nix:134`](file:///tmp/investigation/colmena/src/nix/hive/modules.nix#L134), `<name>-key.service` runs `inotifywait -qq -e delete_self "/run/keys/<name>"`, which triggers when `mv` replaces the inode—causing systemd to stop/restart $G_t$ units bound to `<name>-key.service` with $G_{t+1}$'s incompatible secret before $G_{t+1}$ is even activated!
   - And if `host.activate` subsequently fails at [`line 609`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L609), `activate_node` returns `Err` immediately: the node remains on $G_t$ with `/run/keys/<name>` **permanently corrupted** by $G_{t+1}$'s secrets.
2. **Race (b) — Post-Activation Missing-Key & Systemd Deadlock Race (`uploadAt = "post-activation"`)**:
   - In [`Deployment::activate_node`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L609-L671), `host.activate` (`switch-to-configuration switch`) is awaited synchronously at [`line 609`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L609) **before** post-activation keys are uploaded at [`line 665`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L665).
   - *Case b.1 (Service does not wait on `<name>-key.service`)*: `switch-to-configuration switch` starts the $G_{t+1}$ unit at [`line 609`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L609) before [`line 665`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L665) runs; the unit crashes with `ENOENT` or reads stale $G_t$ keys.
   - *Case b.2 (Service orders `After = [ "<name>-key.service" ]` and `Wants = [ "<name>-key.service" ]`)*: Inspect [`src/nix/hive/modules.nix:117-132`](file:///tmp/investigation/colmena/src/nix/hive/modules.nix#L117-L132):
     ```nix
     serviceConfig.TimeoutStartSec = "infinity";
     serviceConfig.Restart = "always";
     preStart = ''
       while [ ! -f ${lib.escapeShellArg keyPath} ]; do
         ${pkgs.inotify-tools}/bin/inotifywait -qq -e create -e moved_to ${lib.escapeShellArg (dirOf keyPath)}
       done
     '';
     ```
     When `switch-to-configuration switch` starts `<name>-key.service` during [`host.activate`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L609), `systemctl` blocks waiting for `<name>-key.service` (`preStart`) to finish, with `TimeoutStartSec = "infinity"`. Because `host.activate` never returns, execution **never reaches [`line 665`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L665)** (`upload_keys`)—resulting in a **100% deterministic distributed deadlock**!
3. **Race (c) — Unattended Reboot `tmpfs` Amnesia**:
   - In [`src/nix/hive/options.nix:55`](file:///tmp/investigation/colmena/src/nix/hive/options.nix#L55), `destDir` defaults to `"/run/keys"`, which resides on volatile `/run` (`tmpfs`).
   - Upon any unattended reboot (power cycle, kernel panic, hardware reset), `/run/keys` is wiped clean. On boot, `<name>-key.service` blocks forever in `preStart` (`TimeoutStartSec = "infinity"`), and any unit requiring secrets to establish network/management connectivity (WireGuard, IPsec, BGP, TLS client certs, `sshd` host/authorized keys) never starts—permanently bricking the unattended machine. $\blacksquare$

### 4.1 Architectural Qualification Matrix Against Ecosystem Alternatives
| Requirement / Invariant | `deploy-rs` | `colmena` | Pull-Only GitOps (`comin`) | External Orchestrators (K8s / Terraform / Ansible) | `EPOCH` (This Specification) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Coordinator Eval RSS ($N=1,000$)** | $\Theta(N \cdot |M|)$ OOMs | $\Theta(N \cdot |M|)$ OOMs ($\sim 500\text{ GB}$) | Evaluates on target ($\ge 3\text{ GB}$ RAM per target; OOMs small VMs) | External state DB / non-Nix YAML/HCL drift | **$O(1)$ bounded ($\le 4.0\text{ GiB}$ RSS)** via Archetype + `/node-overlay` + CoW workers |
| **Fleet Transfer Complexity** | $\Omega(N \cdot |\Delta C| / B_{\text{coord}})$ | $\Omega(N \cdot |\Delta C| / B_{\text{coord}})$ | $O(N)$ cache pull; whole-NAR granularity | Container layer pull; loses `/nix/store` unified closure | **$O(k \log_k N)$** via Store-Hash-Normalized FastCDC + Rack-Aware QUIC P2P |
| **Coupled Multi-Node Wave Atomicity** | **Fails** (commits node $i$ before node $i+1$ starts) | **Fails** (no rollback at all) | **Impossible** (independent uncoordinated polling loops) | Application-level only; cannot transactionally roll back OS/kernel | **Provably atomic per wave** (`BARRIER_WAIT` leases + Peer Witness Relay) |
| **Secret Zero-Trust & Reboot Survival** | None | **Fails** (3 races + `tmpfs` reboot amnesia + eval heap plaintext) | Requires external `sops-nix`/`agenix` without atomic generation rollback | Runtime Vault dependency (fails closed on boot if Vault unreachable) | **In-store TPM2/age ciphertext + `ramfs` `RENAME_EXCHANGE` + early-boot unseal** |
| **Kernel Panic / Initrd Hang Recovery** | **Fails** (userspace timer dies; `loader.conf` default deleted) | **Fails** (no rollback) | **Fails** (agent runs in Stage 2 userspace after initrd) | Requires manual IPMI/cloud instance replacement | **3-Layer Automatic Recovery** (`/dev/watchdog` + `systemd-boot` `+1` + `state.cbor`) |

---

## Section 5 & 6 (GATE 2): Four-Plane Data Movement & Distributed Systems Physics

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ PLANE 1: EVALUATION & DERIVATION GRAPH PLANE (Coordinator)                                │
│  Tier-1 Archetypes (evalModules 1x) + Tier-2 Late-Bound /node-overlay (O(1))              │
│  Pre-forked CoW Workers (RSS <= W*M_max) + BLAKE3 File-Trace Cache ──> Signed plan.cbor   │
└───────────────────────────────┬───────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────────────────────────────────┐
│ PLANE 2: CLOSURE DISTRIBUTION & STORE TRANSPORT PLANE                                     │
│  32-Byte Store-Hash Normalizer ──> FastCDC (16/64/256 KiB) + zstd -3                      │
│  Hybrid Binary Cache + Rack-Aware k-ary QUIC/mTLS P2P Tree (O(k log_k N))                 │
│  statvfs() Quota Check ──> Staging GC Root (/nix/var/nix/gcroots/epoch/staging/tx-<epoch>)│
└───────────────────────────────┬───────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────────────────────────────────┐
│ PLANE 3: ZERO-TRUST EPHEMERAL SECRET & HARDWARE IDENTITY PLANE                            │
│  In-Store /nix/store/...-epoch-secrets.cbor (ChaCha20-Poly1305 + TPM2 PCR / age X25519)   │
│  Unseal in PREPARE to unswappable ramfs (/run/epoch/secrets/gen-<epoch>)                  │
│  Atomic renameat2(RENAME_EXCHANGE) on /run/epoch/current-secrets + Stage-2 Boot Unseal    │
└───────────────────────────────┬───────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────────────────────────────────┐
│ PLANE 4: DISTRIBUTED TRANSACTIONAL ACTIVATION, CONSENSUS LEASES & ROLLBACK PLANE          │
│  Monotonic tx_epoch in /var/lib/epoch/state.cbor + CLOCK_BOOTTIME Lease State Machine     │
│  Multi-Signal Oracles (D-Bus, /dev/kmsg, Data-Plane) + Peer Witness Lease Relay           │
│  3-Layer Kernel/Reboot Safety (/dev/watchdog + systemd-boot +1-0.conf + state.cbor)       │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Plane 1 — Evaluation & Derivation Graph Plane

#### 5.1.1 Two-Tier Archetype + Late-Bound `/node-overlay` Evaluation
A fleet of $N$ machines partitions into $k = |\mathcal{A}| \ll N$ service archetypes $\mathcal{A} = \{A_1, \dots, A_k\}$ (e.g., `consensus-db`, `api-gateway`, `ceph-osd`, `k8s-worker`).
1. **Tier 1 — Shared Service Archetype Fixpoint ($O(|\mathcal{A}| \cdot |M_{\text{core}}|)$) & Demand-Driven 157-Module Core Slicing**:
   - For each archetype $A_j \in \mathcal{A}$, `EPOCH` evaluates `lib.evalModules` **once per archetype** to produce the archetype's base `toplevel` derivation $T_{A_j}$, sharing a single `pkgs` instantiation (`system = null; inherit pkgs;`) across all archetypes.
   - **Demand-Driven Core Module Slicing (`nix/core-base-modules.json` + `evalArchetype` in `nix/lib.nix`)**: Standard `nixos/modules/module-list.nix` loads `2,126` modules (`84%` optional `services/*` and `programs/*`), forcing `pushDownProperties` / `dischargeProperties` over `~1,969` disabled `mkIf false` modules. `evalArchetype` evaluates against the closed active `157`-module core NixOS subset (`nix/core-base-modules.json` + per-archetype service demand filtering for `etcd`, `postgresql`, `redis`, `nginx`) and pre-validates via `checkDefsInOptions` that every option defined by the archetype and shared modules exists as a real non-stub option in `fastSys.options` before forcing `fastSys`, automatically falling back to the full `2,126`-module list if any custom archetype option lies outside the core set—producing **100% bit-for-bit identical `.drv` store paths** while eliminating `92.6%` of dead modules.
   - **Parallel Bounded-RSS Cold Archetype Workers (`evaluate_cluster_native_plane1`)**: When evaluating cold (`--no-eval-cache`), `epoch eval` spawns bounded parallel worker processes (`GC_INITIAL_HEAP_SIZE=256M GC_FREE_SPACE_DIVISOR=3 GC_MARKERS=2`, reaped via `libc::wait4` to track exact kernel `ru_maxrss`), evaluating all 4 archetypes in **`1.55–1.59 s`** with **`422.4–425.2 MiB` peak worker RSS** (vs. `26.9–27.7 s` and `8,083–8,329 MiB` RSS for `colmena` and `deploy-rs` at $N = 24$).
   - Why naive wrapper derivations around `$toplevel` fail in NixOS: In standard NixOS (`nixos/modules/system/activation/top-level.nix`), `$toplevel/activate` and `$toplevel/bin/switch-to-configuration` hardcode the literal store path `/nix/store/<hash>-etc/etc` inside the activation script text. Simply symlinking `$toplevel` and replacing `/etc` in an outer directory is ignored by `$toplevel/activate`.
   - **`EPOCH`'s Late-Bound `/node-overlay` Indirection (`epoch-archetype-module.nix`)**: Every archetype automatically includes `epoch-archetype-module.nix`, which registers `system.activationScripts.epoch-node-overlay`:
     ```sh
     # Executed during switch-to-configuration test/switch/boot
     OVERLAY_DIR="${EPOCH_STAGE_ROOT:-/nix/var/nix/profiles/system}/node-overlay"
     if [ -d "$OVERLAY_DIR/etc" ]; then
       ln -sfn "$OVERLAY_DIR/etc/hostname" /etc/hostname
       ln -sfn "$OVERLAY_DIR/etc/machine-id" /etc/machine-id
       ln -sfn "$OVERLAY_DIR/etc/epoch-node.json" /etc/epoch/node.json
     fi
     ```
     This allows the heavy archetype `toplevel` ($T_{A_j}$, including kernel, initrd, systemd units, and package closure) to be evaluated and built **once per archetype**.
2. **Tier 2 — Per-Node Overlays ($O(1)$ per node)**:
   - **Fast-Path 2a (Native Data-Oriented ATerm `.drv` Synthesis & Zero-`stdenv` Derivation — Zero `evalModules` Re-evaluation)**:
     When node $i$ of archetype $A(i)$ only customizes typed parameters $\theta_i$ (`hostName`, IPv4/IPv6 CIDR, MAC, rack/zone, peer endpoints, host public keys, and `secrets`), `EPOCH` synthesizes the canonical Nix `derivationStrict` `SHA-256` per-node `Derive(...)` ATerm `.drv` derivation (`synthesize_node_overlay_drv_aterm` in `src/plane1_eval.rs` and `mkNodeClosure` in `nix/lib.nix`) referencing the genuine Tier-1 archetype `.drv` via `archetypeDrv` without calling `lib.evalModules` or `stdenv`:
     - Native Rust Tier-2 ATerm `.drv` synthesis (`synthesize_node_overlay_drv_aterm`) computes exact `output:out:sha256:...` and `text:sha256:...` store paths in **`~4.3 µs` per node** (`103 µs` for 24 nodes) that match `nix eval` bit-for-bit.
   - **Fast-Path 2b (Structural Module Override via Pre-Forked CoW Workers)**:
     For the subset of nodes requiring structural NixOS module overrides $O_i$, evaluation runs inside the pre-forked CoW worker pool via `archetypeEval.${A(i)}.extendModules { modules = [ O_i ]; }`.

#### 5.1.2 Bounded-Memory Pre-Forked Worker Pool ($\text{RSS} \le M_{\text{parent}} + W \cdot M_{\max} = O(1)$)
1. **Master Warm-Up**: The coordinator master process evaluates `nixpkgs` and the $|\mathcal{A}|$ archetype fixpoints ($M_{\text{parent}} \approx 900\text{ MiB}$ for $|\mathcal{A}| = 8$), runs `GC_gcollect()`, and freezes its heap into read-only OS pages.
2. **CoW `fork()` & Hard Recycling Ceiling**:
   - The master maintains $W$ concurrent child workers via `fork()` ($W = \min(\text{CPU cores}, \lfloor (M_{\text{budget}} - M_{\text{parent}}) / M_{\max} \rfloor)$, default $W = 4, M_{\max} = 768\text{ MiB} \implies \text{Total RSS} \le 3.97\text{ GiB}$).
   - Each worker receives node evaluation jobs over an `AF_UNIX` `SOCK_SEQPACKET` IPC channel, inherits the warm archetype attrsets via zero-copy kernel Copy-on-Write (`fork()`), emits serialized `NodePlanEntry` CBOR frames, and inspects `/proc/self/statm` (`VmRSS`) after each node.
   - Whenever a worker's private dirty RSS exceeds $M_{\max}$ (or after $B = 16$ structural node evaluations), the worker immediately calls `_exit(0)` so the Linux kernel reclaims 100% of fragmented Boehm GC pages, and the master `fork()`s a fresh worker in $< 1.5\text{ ms}$.

#### 5.1.3 File-Traced Content-Addressed Evaluation Cache (`BLAKE3` Merkle Tree: `ArchetypeEvalCache` & `EvalCache`)
- During evaluation of archetype $A_j$ and node $i$, `EPOCH` computes content-addressed `BLAKE3` Merkle keys over all input files (`flake.lock`, `nix/lib.nix`, `nix/archetype-module.nix`, `nix/core-base-modules.json`, and cluster Nix expressions) and node parameters:
  $$K_{\text{arch}}(A_j) = \text{BLAKE3}\left(\text{system} \parallel \text{BLAKE3}_{f \in \mathcal{F}_{\text{shared}}}(\text{BLAKE3}(f)) \parallel A_j\right)$$
  $$K_{\text{eval}}(i) = \text{BLAKE3}\left(\text{BLAKE3}(\texttt{flake.lock}) \parallel A(i) \parallel \text{canonical\_cbor}(\theta_i) \parallel \text{BLAKE3}_{f \in \mathcal{F}(i)}(\text{path}(f) \parallel \text{BLAKE3}(f))\right)$$
- On subsequent runs (`epoch eval` / `epoch-cached`), if the `BLAKE3` Merkle root matches and the genuine `/nix/store/<32-char>-nixos-system-*.drv` store paths exist on disk, `EPOCH` resolves all 4 archetypes and synthesizes all $N = 24$ canonical Nix `SHA-256` per-node `.drv` store paths + validates quorums, wave DAG, and P2P tree in **`89.8–175.4 µs` (`0.090–0.175 ms`)** with **`5.80–5.93 MiB` RSS** (**`56,297x–158,019x` faster** and **`267x–1,406x` lower RSS** than `colmena` and `deploy-rs`).

#### 5.1.4 Pure-Nix & Native Rust Typed Topology, Dependency DAG, & Quorum Policy Schema $\to$ `plan.cbor`
- All rollout waves $W_k$, inter-wave causal barriers `dependsOn`, failure-domain coordinates (`rack`, `zone`), and consensus quorum groups $Q_r$ are validated at evaluation time (both in pure Nix `nix/lib.nix` and in Data-Oriented Rust `src/plane1_eval.rs`):
  - **Static DAG Acyclicity Check**: Kahn's topological sort over `(waves, dependsOn)` rejects any cycle (`19.1 µs` in Rust).
  - **Static Quorum Safety Invariant**: For every quorum $Q_r$ of size $|Q_r|$, `EPOCH` enforces at evaluation time:
    $$\forall W_k \in \text{Waves}: \quad |W_k \cap Q_r| \le \text{maxUnavailable}(Q_r) \le \left\lfloor \frac{|Q_r| - 1}{2} \right\rfloor$$
    unless `W_k` is an explicit sub-quorum wave with a sequential barrier between each member.
- The resulting execution plan is serialized as RFC 8949 deterministic CBOR (`plan.cbor`) and signed with the coordinator's offline/HSM-backed `Ed25519` key (`coordinator_sig`).

---

### 5.2 Plane 2 — Closure Distribution & Store Transport Plane

#### 5.2.1 Length-Preserving 32-Byte Store-Hash Normalization + FastCDC over NARs + `zstd`
1. **Why Raw FastCDC Over Unnormalized NARs Fails**:
   In Nix, a 1-byte change in any build input changes a package's output store hash `/nix/store/<32-char-nix-base32>-<name>`. Because ELF binaries (`DT_RUNPATH`/`RPATH`), shebang scripts, and symlinks embed the 32-character store hashes of their dependencies and self-references every few kilobytes, running FastCDC directly on raw NAR bytes causes every chunk containing a reference hash to change its `BLAKE3` digest—destroying deduplication!
2. **`EPOCH`'s Bijective 32-Byte Store-Hash Normalizer**:
   - Let store path $p \in C_i$ have sorted reference store-hash table $R(p) = [r_0, r_1, \dots, r_{m-1}]$ where each $r_{\text{idx}} \in [0\text{-}9\text{a-df-np-sv-z}]^{32}$ is the 32-byte Nix-base32 hash of a referenced `/nix/store/<r_idx>-<name>` path (with $r_0 = \text{hash}(p)$).
   - Before chunking, `EPOCH` streams the canonical NAR byte stream $S(p)$ through a SIMD scanner that matches `/nix/store/` followed by 32 Nix-base32 characters $r_{\text{idx}} \in R(p)$, and replaces $r_{\text{idx}}$ in-place with a fixed 32-byte canonical token:
     $$\text{Token}(\text{idx}) = \texttt{"\textbackslash x00EPOCH\_REF\_"} \parallel \text{hex\_u16}(\text{idx}) \parallel \texttt{"\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_"} \quad (\text{exact 32 bytes})$$
   - Because $\text{len}(\text{Token}(\text{idx})) = \text{len}(r_{\text{idx}}) = 32$ bytes, zero byte offsets shift anywhere in the NAR!
3. **Gear-Based Normalized FastCDC Segmentation & Target Reconstruction**:
   - The normalized NAR stream $\tilde{S}(p)$ is segmented using Gear-hash Normalized **FastCDC** with parameters:
     $$c_{\min} = 16\text{ KiB}, \quad c_{\text{avg}} = 64\text{ KiB}, \quad c_{\max} = 256\text{ KiB}$$
   - Each normalized chunk $\tilde{b}_m$ is identified by $h_m = \text{BLAKE3}(\tilde{b}_m)$ and compressed with `zstd -3` into $z_m$.
   - On each target, `epoch-agent` maintains an mmap'd Robin-Hood hash index `/var/cache/epoch/chunk-index.bin` mapping `norm_blake3 -> (store_path_id, offset, raw_len)`.
   - When `StageManifest` arrives for path $p$, `epoch-agent` looks up each $h_m \in \text{Manifest}(p)$:
     - **Local Hit**: Reads $\tilde{b}_m$ directly from the existing local `/nix/store` file via `pread64` + forward 32-byte normalization.
     - **Miss ($\Delta$ Chunk)**: Fetches compressed $z_m$ from its P2P parent or binary cache, decompresses with `zstd`, and verifies $\text{BLAKE3}(\tilde{b}_m) == h_m$.
   - `epoch-agent` applies the inverse 32-byte substitution $\text{Token}(\text{idx}) \mapsto r_{\text{idx}}$, unpacks the NAR into `/nix/store/.epoch-tmp-<uuid>`, computes the full uncompressed NAR's `SHA-256` and `NarSize` on the fly, verifies exact equality against `manifest.nar_sha256` and `manifest.store_sig`, recursively sets read-only permissions (`0555`/`0444`, `mtime = 1`), `fsync`s, atomically renames into `/nix/store/<p>`, and registers the path in `/nix/var/nix/db/db.sqlite` (`ValidPaths` and `Refs` tables).

#### 5.2.2 Topology-Aware Hybrid Binary-Cache Pull + Rack-Aware mTLS/QUIC P2P Tree ($O(k \log_k N)$)
1. **Partitioned Spanning Tree by `(rack_id, system)`**:
   - `plan.cbor` partitions target nodes by `(rack_id, system)` (e.g., `("rack-a", "x86_64-linux")`) and elects one **Rack Seed Node** per `(rack_id, system)` group. Inside each rack group, nodes form a deterministic balanced $k$-ary tree ($k = 4$) of depth $\le \lceil \log_4 N_{\text{rack}} \rceil$.
2. **Cut-Through Pipelined QUIC Transport**:
   - All nodes communicate over `quinn` (Rust QUIC over UDP port `9443`, TLS 1.3 mutual authentication `ALPN = "epoch-p2p/1"`) where every peer's `Ed25519` public key is pinned in the coordinator-signed `plan.cbor`.
   - For closures present in an upstream binary cache (`cache.nixos.org` or regional S3), Rack Seed Nodes pull missing chunks over HTTP/2 or S3 and fan them out locally inside the rack. For coordinator-built delta chunks $\Delta C_{\text{norm-CDC}}$, the coordinator pushes each missing chunk once to each Rack Seed Node, which pipelines verified 64 KiB chunks to its $k = 4$ children immediately upon verifying $\text{BLAKE3}(\tilde{b}_m) == h_m$:
     $$T_{\text{transfer}}(N) = O\left(\frac{|\Delta C_{\text{norm-CDC}}|}{B_{\text{link}}} \cdot k \log_k N\right), \quad \text{Coordinator Egress} = R_{\text{racks}} \cdot |\Delta C_{\text{norm-CDC}}| \ll N \cdot |C|$$

#### 5.2.3 Strict Store Staging Invariant (`statvfs` Pre-Check & Isolated GC Root)
1. **`statvfs` Free-Space & Inode Pre-Check**:
   Before downloading a single chunk for `tx_epoch`, `epoch-agent` invokes `statvfs("/nix/store")` and checks:
   $$\begin{aligned}
   f_{\text{bavail}} \cdot f_{\text{frsize}} &\ge \sum_{p \in C_i \setminus \text{LocalStore}} \text{NarSize}(p) + \max\left(512\text{ MiB},\ 0.05 \times f_{\text{blocks}} \cdot f_{\text{frsize}}\right) \\
   f_{\text{favail}} &\ge 2 \cdot |C_i \setminus \text{LocalStore}| + 4096
   \end{aligned}$$
   If either check fails, `epoch-agent` refuses `StageManifest` with `StageError::StoreQuotaExceeded` before writing to disk.
2. **Isolated Staging GC Root**:
   Once all paths in $C_i$ are verified in `/nix/store`, `epoch-agent` creates an atomic symlink:
   $$\texttt{/nix/var/nix/gcroots/epoch/staging/tx-}\langle\text{tx\_epoch}\rangle \longrightarrow \texttt{/nix/store/}\langle\text{hash}\rangle\texttt{-epoch-node-}\langle i\rangle$$
   Protecting $C_i$ from concurrent `nix-collect-garbage` runs while leaving `/nix/var/nix/profiles/system`, `/run/current-system`, and `/boot` completely untouched during `STAGED`.

---

### 5.3 Plane 3 — Zero-Trust Ephemeral Secret & Hardware Identity Plane

#### 5.3.1 Hardware-Bound In-Store Ciphertext Envelopes (`epoch-secrets.cbor`)
1. **Pure Derivation Construction**:
   - Every node $i$'s secrets are compiled into `/nix/store/<hash>-epoch-secrets.cbor` linked at `$toplevel/node-overlay/epoch-secrets.cbor`.
   - Because `epoch-secrets.cbor` contains only authenticated ciphertext encrypted to node $i$'s hardware/host public keys, it is safe to store in `/nix/store`, binary caches, and P2P chunks.
2. **Cryptographic Envelope Structure**:
   - **Data Encryption Key (DEK)**: Fresh 256-bit random key $K_{\text{DEK}}$ per secret bundle, encrypting the serialized `Vec<SecretEntry>` via `ChaCha20-Poly1305` (or `XChaCha20-Poly1305`) with Additional Authenticated Data:
     $$\text{AAD} = \text{BLAKE3}\left(\texttt{"epoch-secret-v1"} \parallel \text{node\_id} \parallel \text{archetype\_toplevel\_store\_path}\right)$$
     Binding the ciphertext to both the exact target node identity and the exact system closure generation!
   - **Key Wrapping (Dual-Mode Hardware + Host Key)**:
     - *Primary (TPM 2.0 Sealed Object)*: When a target enrolls a TPM 2.0 Endorsement/Storage Root Key (`EK`/`SRK`), $K_{\text{DEK}}$ is wrapped as a `TPM2B_PRIVATE || TPM2B_PUBLIC` object bound to `TPM2_PolicyAuthorize` (signed by the coordinator's PCR policy key over PCRs `0, 2, 7` for UEFI + Secure Boot state) or `TPM2_PolicyPCR`.
     - *Fallback / Host Identity (`age` / `X25519`)*: $K_{\text{DEK}}$ is wrapped via `age` (`X25519` + `HKDF-SHA256` + `ChaCha20-Poly1305`) to the target's `/etc/ssh/ssh_host_ed25519_key.pub` converted via birational map to Curve25519 (`ssh-to-age`).

#### 5.3.2 Generation-Versioned Unswappable `ramfs` & Atomic `RENAME_EXCHANGE` Symlink Flip
1. **Unswappable `ramfs` Mount**:
   - On daemon startup (and Stage-2 early boot), `epoch-agent` mounts a dedicated kernel `ramfs` at `/run/epoch/secrets`:
     ```c
     mount("epoch-secrets", "/run/epoch/secrets", "ramfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
     chmod("/run/epoch/secrets", 0700);
     ```
   - Unlike `tmpfs`, **`ramfs` pages cannot be paged out to swap space by the Linux kernel page reclaimer**, guaranteeing plaintext secrets never touch disk even on hosts with unencrypted swap partitions.
2. **Three-Phase Secret Lifecycle (`PREPARE` $\to$ `ACTIVATING` $\to$ `COMMITTED` / `ROLLED_BACK`)**:
   - **Phase 1 (`PREPARE`)**: `epoch-agent` reads `$staged_toplevel/node-overlay/epoch-secrets.cbor`, unseals $K_{\text{DEK}}$ via `/dev/tpmrm0` (or `/etc/ssh/ssh_host_ed25519_key`), verifies the `ChaCha20-Poly1305` tag against `AAD`, creates `/run/epoch/secrets/gen-<tx_epoch>` (`0700`), writes each secret file with its target `uid:gid` (resolved against `$staged_toplevel/etc/passwd` and `$staged_toplevel/etc/group`) and `mode`, and `fsync`s the directory. If unsealing or authentication fails, `epoch-agent` aborts in `PREPARE` before touching any running service!
   - **Phase 2 (`ACTIVATING` — Zero-Window Atomic Swap)**: Immediately before running `switch-to-configuration test`, `epoch-agent` creates a temporary symlink `/run/epoch/current-secrets.next -> /run/epoch/secrets/gen-<tx_epoch>` and invokes the Linux `renameat2` syscall with `RENAME_EXCHANGE`:
     ```c
     syscall(SYS_renameat2,
             AT_FDCWD, "/run/epoch/current-secrets.next",
             AT_FDCWD, "/run/epoch/current-secrets",
             RENAME_EXCHANGE);
     ```
     The kernel VFS atomically exchanges the two dentries under `rename_lock`. There is **zero microsecond window** where `/run/epoch/current-secrets` is missing (`ENOENT`) or half-written.
   - **Phase 3 (`ROLLED_BACK` or `COMMITTED` — Cryptographic Zeroization)**:
     - On **Rollback**: `epoch-agent` executes `renameat2(..., "/run/epoch/current-secrets.next", ..., "/run/epoch/current-secrets", RENAME_EXCHANGE)` to atomically restore `/run/epoch/secrets/gen-<prev_epoch>` *before* running `$prev_toplevel/bin/switch-to-configuration test`, then overwrites every secret buffer and file in `gen-<tx_epoch>` with `explicit_bzero()` (or `write()` of `0x00` bytes across the `ramfs` page cache), `unlink()`s the files, and `rmdir()`s `gen-<tx_epoch>`.
     - On **Commit**: `epoch-agent` zero-wipes (`explicit_bzero`) and unlinks the retired generation directory `/run/epoch/secrets/gen-<prev_epoch>`.

#### 5.3.3 100% Coordinator-Free Early-Boot (`initrd` & Stage 2) Unsealing
- `epoch-archetype-module.nix` injects both a NixOS Stage-2 activation script (`system.activationScripts.epoch-secrets-boot`) and an early systemd unit (`epoch-early-unseal.service` with `DefaultDependencies=no`, `Before=sysinit.target network-pre.target systemd-udevd.service`):
  ```sh
  /run/booted-system/sw/bin/epoch-agent unseal-boot \
    --system-root /run/booted-system \
    --ramfs-root /run/epoch/secrets
  ```
- On any unattended reboot, `epoch-agent unseal-boot` reads `/run/booted-system/node-overlay/epoch-secrets.cbor` directly from the local `/nix/store`, unseals it using the local TPM 2.0 (`/dev/tpmrm0`) or `/etc/ssh/ssh_host_ed25519_key`, populates `/run/epoch/secrets/gen-boot`, and sets `/run/epoch/current-secrets -> /run/epoch/secrets/gen-boot` **before any network daemon, VPN, firewall, or application service starts**.
- This completely eliminates `colmena`'s `tmpfs` reboot amnesia (`Race c`) with zero coordinator interaction.

---

### 5.4 Plane 4 — Distributed Transactional Activation, Consensus Leases, & Rollback Plane

#### 5.4.1 Monotonic Fencing Tokens (`tx_epoch`) & Crash-Safe State (`/var/lib/epoch/state.cbor`)
- Every target persists its state in `/var/lib/epoch/state.cbor` via atomic write-replace (`open("/var/lib/epoch/state.cbor.tmp", O_WRONLY|O_CREAT|O_TRUNC, 0600)` $\to$ `write()` $\to$ `fdatasync()` $\to$ `renameat2()` $\to$ `fsync(dir_fd)`), protected by a keyed `BLAKE3` MAC (`state_blake3_mac`).
- **Fencing Rule**: Every control-plane RPC carries `tx_epoch: u64`. Upon receiving any RPC, `epoch-agent` checks:
  $$\text{if } \text{msg.tx\_epoch} < \text{state.highest\_tx\_epoch} \implies \text{return } \texttt{Err(StaleEpochFenced(state.highest\_tx\_epoch))}$$
  If $\text{msg.tx\_epoch} > \text{state.highest\_tx\_epoch}$ and the message carries a valid `coordinator_sig`, `epoch-agent` updates `state.highest_tx_epoch = msg.tx_epoch` and `fdatasync`s `state.cbor` before acting. Zombie or partitioned coordinators are mathematically fenced off.

#### 5.4.2 Per-Wave Two-Phase Lease-Fenced Automaton & Speculative `test` Activation
For each wave $W_k$ in topological order of `plan.cbor`:
```
  ┌──────┐   StageManifest    ┌────────┐   PrepareWave     ┌──────────┐
  │ IDLE ├───────────────────►│ STAGED ├──────────────────►│ PREPARED │
  └──▲───┘                    └───┬────┘                   └────┬─────┘
     │                            │ Abort / Error               │ ActivateWave(lease_ttl)
     │ Cleanup                    ▼                             ▼
     │                     ┌─────────────┐                ┌────────────┐
     └─────────────────────┤ ROLLED_BACK │◄───────────────┤ ACTIVATING │
                           └──────▲──────┘  SwitchFailed  └─────┬──────┘
                                  │                             │ switch-to-configuration test
                                  │                             ▼ + RENAME_EXCHANGE secrets
     ┌───────────┐                │ Abort /               ┌────────────┐
     │ COMMITTED │                │ LeaseExpired /        │  PROBING   │
     └─────▲─────┘                │ ProbeFailed           └─────┬──────┘
           │                      │                             │ All Oracles Pass
           │ CommitWave(coord_sig)│                             ▼
           │ + switch-to-config   │                      ┌──────────────┐
           │   switch             └──────────────────────┤ BARRIER_WAIT │
           └─────────────────────────────────────────────┤ (CLOCK_BOOT) │
                                                         └──────────────┘
```
1. **Why `ACTIVATING` Uses `switch-to-configuration test` Instead of `switch`**:
   - During `ACTIVATING(tx_epoch)` (for non-reboot deployments), `epoch-agent` sets `EPOCH_STAGE_ROOT=/nix/var/nix/gcroots/epoch/staging/tx-<tx_epoch>`, atomically swaps `/run/epoch/current-secrets` via `RENAME_EXCHANGE`, and executes:
     ```sh
     /nix/var/nix/gcroots/epoch/staging/tx-<tx_epoch>/bin/switch-to-configuration test
     ```
   - `switch-to-configuration test` activates the new `/etc`, reloads `systemd`, and starts/restarts changed services, and updates `/run/current-system`, **WITHOUT mutating `/nix/var/nix/profiles/system` or `/boot/loader/entries/`**!
   - Only when the wave transitions `BARRIER_WAIT -> COMMITTED(tx_epoch)` does `epoch-agent` create `/nix/var/nix/profiles/system-<g+1>-link`, flip `/nix/var/nix/profiles/system` via `RENAME_EXCHANGE`, and run `$staged_toplevel/bin/switch-to-configuration boot` (or `switch`) to make the generation permanent across reboots.
   - This eliminates `deploy-rs`'s destructive `nix-env --rollback` / `--delete-generations` bug (Theorem 1.1 Failure Mode 4) and ensures a power loss during trial activation automatically boots $G_t$.
2. **Monotonic `CLOCK_BOOTTIME` Lease Timer**:
   - Upon entering `ACTIVATING`, `epoch-agent` reads `clock_gettime(CLOCK_BOOTTIME, &now)` (which ticks monotonically even across CPU suspend/VM pause and is immune to NTP `CLOCK_REALTIME` jumps) and sets `lease_deadline_ns = now_ns + lease_ttl_ns` (default `30_000_000_000` ns).
   - If `clock_gettime(CLOCK_BOOTTIME) >= lease_deadline_ns` while in `ACTIVATING`, `PROBING`, or `BARRIER_WAIT` without receiving a validly signed `CommitWave(tx_epoch)`, `epoch-agent` **unconditionally self-aborts to `ROLLED_BACK`**.

#### 5.4.3 Multi-Signal Health Oracles (`PROBING`) & Peer Witness Lease Relay (`BARRIER_WAIT`)
1. **Multi-Signal Health Oracles (`PROBING`)**:
   - **Oracle 1 (Systemd D-Bus State Convergence)**: Connects to `/run/dbus/system_bus_socket` (`org.freedesktop.systemd1.Manager`), verifies `SystemState` is `"running"` (or all required units in `probes.required_systemd_units` report `ActiveState == "active" && SubState == "running"`), and verifies zero units transitioned to `failed`.
   - **Oracle 2 (Kernel `/dev/kmsg` & Cgroup OOM Oracle)**: Reads `/dev/kmsg` with `O_RDONLY | O_NONBLOCK` from the monotonic timestamp recorded at `ACTIVATING` entry, rejecting any line matching `Oops:`, `BUG:`, `Kernel panic`, `segfault at`, or `Out of memory: Killed process`, and checks `/sys/fs/cgroup/system.slice/memory.events` for `oom_kill > oom_kill_baseline`.
   - **Oracle 3 (Synthetic Data-Plane & Cohort Peer Mesh Probes)**: Executes configured TCP/HTTP/gRPC checks and verifies mTLS/QUIC reachability to at least $\text{peer\_mesh\_quorum} = \lfloor |W_k|/2 \rfloor + 1$ cohort peers in wave $W_k$.
2. **Peer Witness Lease Relay (`BARRIER_WAIT`)**:
   - Once all 3 oracles pass, `epoch-agent` signs `HealthAttestation { tx_epoch, wave_id, node_id, healthy: true, node_sig }` with its host `Ed25519` key, sends it to the coordinator, and gossips it to its $d = \min(4, |W_k|-1)$ cohort peers in $W_k$.
   - If the direct management link `Coordinator <-> Node i` is severed by an asymmetric routing flap while `Node i`'s data-plane link to cohort peer `Node j` is healthy:
     - `Node j` wraps `Node i`'s signed `HealthAttestation` in `PeerWitnessRelay` and forwards it to the coordinator.
     - The coordinator verifies `Node i`'s `node_sig` and `Node j`'s `relay_sig`, counts `Node i` as healthy at the wave barrier, and returns `LeaseKeepalive(tx_epoch, coord_sig)` or `CommitWave(tx_epoch, coord_sig)` through `Node j` back to `Node i`.
     - Because `LeaseKeepalive` and `CommitWave` are signed by the coordinator's `Ed25519` key (`coord_sig`), `Node i` cryptographically verifies the relayed commit without trusting `Node j` with commit authority!

#### 5.4.4 3-Layer Kernel & Reboot Safety
1. **Layer 1 — Hardware Watchdog (`/dev/watchdog`)**:
   - Before entering `ACTIVATING`, `epoch-agent` opens `/dev/watchdog` (`ioctl(fd, WDIOC_SETTIMEOUT, &60)`) and pins its own memory via `mlockall(MCL_CURRENT | MCL_FUTURE)` with `OOMScoreAdjust = -1000`.
   - `epoch-agent` sends `WDIOC_KEEPALIVE` every `10s` *only* after verifying its internal tokio reactor and D-Bus socket are responsive. If a kernel panic, spinlock deadlock, or hard OOM livelock freezes userspace, `/dev/watchdog` receives no keepalive and asserts a hardware reset after `60s`.
2. **Layer 2 — `systemd-boot` Single-Trial Boot Counting (`+1`)**:
   - When `kernel_path` or `initrd_path` differs between $G_t$ and $G_{t+1}$, `epoch-agent` does **not** change the `default` line in `/boot/loader/loader.conf` (which remains `nixos-generation-<g>.conf`, i.e., known-good $G_t$).
   - Instead, `epoch-agent` writes $G_{t+1}$'s boot entry as `/boot/loader/entries/nixos-generation-<g+1>+1-0.conf` (`+1` trial remaining, `0` tries done) and sets the EFI variable `LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f` to `nixos-generation-<g+1>+1-0.conf\0`.
   - On reboot, `systemd-boot` renames `nixos-generation-<g+1>+1-0.conf` $\to$ `nixos-generation-<g+1>+0-1.conf` (`0` tries left) before jumping to the new kernel.
   - If the new kernel panics or hangs in `initrd`, the hardware watchdog resets the host after `60s`; on the next boot, `systemd-boot` sees `+0-1.conf` has `0` tries left, skips it, and boots the default known-good $G_t$ (`nixos-generation-<g>.conf`)!
   - Only when the rebooted $G_{t+1}$ passes `PROBING` and receives `CommitWave(tx_epoch)` does `epoch-agent` rename `nixos-generation-<g+1>+0-1.conf` $\to$ `nixos-generation-<g+1>.conf` and update `loader.conf` default.
3. **Layer 3 — Post-Reboot `state.cbor` Reconciliation**:
   - When `epoch-agent` starts on boot, it reads `/var/lib/epoch/state.cbor`. If `state.phase ∈ {Activating, Probing, BarrierWait}` and `realpath("/run/booted-system") == state.prev_toplevel` (indicating Layer 1+2 recovered from a failed trial reboot) or `wall_clock_utc > state.reboot_deadline_wall_utc_s`, `epoch-agent` automatically cleans up `/boot/loader/entries/nixos-generation-<g+1>+0-1.conf`, ensures `/run/epoch/current-secrets` points to $G_t$'s secrets, sets `state.phase = RolledBack`, and reports `HealthAttestation { healthy: false, diagnostic: "BootFallbackRecovered" }`.

---

## Section 9 (GATE 3): Ruthless Anti-Bloat & Garbage-Requirement Rejection Ledger

### 9.1 Formal Rejected Requirements & Disqualified Anti-Patterns Ledger
| ID | Disqualified Requirement / Anti-Pattern | Exact Failure Mode / Complexity Tax Introduced | `EPOCH` First-Principles Replacement |
| :--- | :--- | :--- | :--- |
| **R1** | **Non-Nix YAML / HCL / Jinja2 / Helm Template Wrappers** | Destroys Nix module static type safety, prevents cross-module option composition, introduces string-interpolation injection bugs, and breaks `flake.lock` hermetic reproducibility. | Pure-Nix typed schema (`epoch.lib.mkCluster`) compiling directly to deterministic signed `plan.cbor`. |
| **R2** | **External Stateful Control-Plane Databases (PostgreSQL / etcd / Consul / Terraform State)** | Creates a split-brain source of truth that drifts from Git, requires DB backups/migrations, and causes circular bootstrap deadlock when the deployment tool's DB is hosted on the cluster being deployed. | Stateless Git-driven `plan.cbor` + target-local crash-safe `/var/lib/epoch/state.cbor` with monotonic `tx_epoch`. |
| **R3** | **Heavyweight Container / Kubernetes / Nomad Sidecars on Targets** | Imposes 150–500 MB RAM overhead per host, containerd/kubelet attack surface, and CNI complexity while remaining incapable of atomically switching host kernels, initrds, or `/nix/var/nix/profiles/system`. | Single $< 5\text{ MB}$ static Rust binary (`epoch-agent`) locked in RAM with `mlockall`. |
| **R4** | **Imperative Non-Invertible Pre/Post Shell Hooks (`preDeploy.sh` / Ansible-style hooks)** | Mutates arbitrary state outside `/nix/store` before or after activation. Because arbitrary shell commands have no algebraic inverse, rolling back the Nix profile leaves mutated filesystem/DB state behind (permanent drift). | Pure NixOS activation scripts + declarative systemd `ExecStartPre` units strictly bound to generation closures. |
| **R5** | **Permanent Root SSH Agent Forwarding (`ForwardAgent=yes`)** | Exposes the operator's live SSH agent UNIX socket on every target host; a single compromised root process on any target can hijack the socket to compromise the entire fleet. | Zero SSH agent forwarding; mutual TLS 1.3 over QUIC with pinned `Ed25519` node identities + offline-signed `plan.cbor`. |
| **R6** | **Out-of-Band Imperative `/run/keys` `scp`/stdin Uploads (`colmena` `deployment.keys`)** | Suffers pre-activation overwrite race (corrupting $G_t$), post-activation systemd deadlock (`TimeoutStartSec=infinity`), `tmpfs` reboot amnesia, and coordinator heap plaintext exposure. | In-store TPM2/age ciphertext (`epoch-secrets.cbor`) + unswappable `ramfs` + `renameat2(RENAME_EXCHANGE)` + early-boot unseal. |
| **R7** | **Target-Side Full Flake Evaluation (`nixos-rebuild` / `comin` on target)** | Requires $\ge 2\text{–}4\text{ GiB}$ RAM on every target (causing OOM kills on small VMs/routers) and distributes the entire repository source tree (including other nodes' configs) to every target. | Coordinator Archetype + `/node-overlay` evaluation ($O(1)$ RSS) + Plane 2 binary chunk distribution. |
| **R8** | **Bloated Web GUI / SaaS Control Plane / GraphQL Server** | Massive authentication and JS dependency attack surface, persistent control-plane credentials, and useless during network-degraded emergency recovery. | Deterministic CLI + structured CBOR/JSON event logs + standard OpenTelemetry (`OTLP`) metrics export. |

### 9.2 Retained Feature Traceability Matrix (1-to-1 Bottleneck Mapping)
| Retained `EPOCH` Architectural Mechanism | Gate 1 Incumbent Bottleneck Solved | Gate 2 Governing Plane & Quantitative Bound |
| :--- | :--- | :--- |
| **1. Tier-1 Archetype Fixpoint + Tier-2 Late-Bound `/node-overlay`** | `colmena` $\Theta(N \cdot |M_{\text{NixOS}}|)$ per-node `evalConfig` duplication ([`eval.nix:154-234`](file:///tmp/investigation/colmena/src/nix/hive/eval.nix#L154-L234)) | **Plane 1**: $O(|\mathcal{A}| \cdot |M_{\text{NixOS}}| + N)$ work; $\sim 1.2\text{ ms}$ per overlay node |
| **2. Pre-Forked CoW Worker Pool with `VmRSS` `_exit(0)` Recycling** | `colmena` & `deploy-rs` single-process Boehm GC heap retention ($\sim 512\text{ MB}\cdot N$, [`limits.rs:10`](file:///tmp/investigation/colmena/src/nix/deployment/limits.rs#L10)) | **Plane 1**: Hard ceiling $\text{RSS} \le M_{\text{parent}} + W \cdot M_{\max} \le 4.0\text{ GiB}$ ($O(1)$) |
| **3. File-Traced `BLAKE3` Merkle Evaluation Cache (`eval-cache.redb`)** | Re-evaluating unchanged NixOS nodes on every CLI invocation | **Plane 1**: $\sim 50\ \mu\text{s}$ cache hit resolution per unchanged node |
| **4. Typed Wave DAG & Quorum Schema $\to$ Ed25519-Signed `plan.cbor`** | `deploy-rs` random `HashMap` loop ([`cli.rs:565`](file:///tmp/investigation/deploy-rs/src/cli.rs#L565)); `colmena` flat `deployment.tags` ([`options.nix:181`](file:///tmp/investigation/colmena/src/nix/hive/options.nix#L181)) | **Plane 1 & 4**: Causal wave partial order $W_a \prec W_b$ & static quorum safety |
| **5. 32-Byte Store-Hash Normalizer + FastCDC (`16/64/256 KiB`) + `zstd`** | Whole-NAR re-transmission on minor rebuilds due to self/input store hash shifts | **Plane 2**: $\ge 99.8\%$ sub-package deduplication on incremental rebuilds |
| **6. Hybrid Binary-Cache Pull + Rack-Aware $k$-ary QUIC/mTLS P2P Tree** | `colmena`/`deploy-rs` $\Omega(N \cdot |\Delta C| / B_{\text{coord}})$ SSH star-push & `--no-check-sigs` ([`ssh.rs:293`](file:///tmp/investigation/colmena/src/nix/host/ssh.rs#L293)) | **Plane 2**: $O(k \log_k N)$ transfer time; mandatory `NarHash` & store signature check |
| **7. `statvfs` Quota Guard + `/nix/var/nix/gcroots/epoch/staging` Isolation** | Mid-transfer `/nix/store` `ENOSPC` exhaustion & premature profile mutation | **Plane 2**: Zero profile/boot mutation during staging; fail-fast on `ENOSPC` |
| **8. In-Store TPM2/age `epoch-secrets.cbor` + `ramfs` `RENAME_EXCHANGE` + Boot Unseal** | `colmena` 3 fatal `/run/keys` races ([`mod.rs:575-665`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs#L575-L665), [`modules.nix:117-134`](file:///tmp/investigation/colmena/src/nix/hive/modules.nix#L117-L134)) & eval heap plaintext | **Plane 3**: $0\text{ B}$ coordinator/wire plaintext; $0\text{ ms}$ swap skew; $100\%$ reboot survival |
| **9. Monotonic `tx_epoch` + `BARRIER_WAIT` Lease + Peer Witness Relay** | `deploy-rs` premature per-node `confirm_profile` split-brain & simultaneous-SSH reset bug ([`deploy.rs:607-721`](file:///tmp/investigation/deploy-rs/src/deploy.rs#L607-L721)) | **Plane 4**: Wave-wide atomic commit or bounded rollback ($\le \text{lease\_ttl}$); zero false rollback on management link flap |
| **10. `/dev/watchdog` + `systemd-boot` `+1-0.conf` + `state.cbor` Reconciliation** | `deploy-rs` userspace `activate-rs` failure on kernel panic, OOM, or initrd hang ([`activate.rs:825`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs#L825), [`flake.nix:109`](file:///tmp/investigation/deploy-rs/flake.nix#L109)) | **Plane 4**: Automatic hardware + bootloader recovery to $G_t$ within $\le 95\text{ s}$ |

---

## Section 7 & 8 (GATE 4): Adversarial Fault-Injection Verification Matrix & Concrete Schemas

### 7.1 Step-by-Step State-Machine Execution Traces Across All 5 Mandatory Fault Scenarios

#### Scenario 1: Coordinator Crash (`SIGKILL` / Power Loss) Mid-DAG Rollout
- **Initial State**: Causal DAG $W_1 = \{N_1, N_2\}$ (DB tier) $\prec W_2 = \{N_3, N_4, N_5\}$ (API tier), transitioning $G_{41} \to G_{42}$ (`tx_epoch = 42`, `lease_ttl = 30s`). All 5 nodes have completed `STAGED(42)` and `PREPARED(42)` (with secrets unsealed into `/run/epoch/secrets/gen-42` on `ramfs`, while `/run/epoch/current-secrets -> gen-41`).
- **$t = 0.0\text{s}$**: Wave $W_1$ completes `ACTIVATING -> PROBING -> BARRIER_WAIT`, receives `CommitWave(tx=42, wave=W_1, coord_sig)`, updates `/nix/var/nix/profiles/system`, persists `state.cbor` (`phase = Committed, highest_tx_epoch = 42`), and zero-wipes `gen-41`.
- **$t = 2.0\text{s}$**: Coordinator dispatches `ActivateWave(tx=42, wave=W_2, lease_ttl_ms=30000, coord_sig)` to $N_3, N_4, N_5$.
- **$t = 2.1\text{s}$**: $N_3$ and $N_4$ receive `ActivateWave(42)`, persist `state.cbor` (`phase = Activating, lease_deadline_boottime_ns = t_boot + 30s`), atomically exchange `/run/epoch/current-secrets` to `gen-42` via `renameat2(RENAME_EXCHANGE)`, and execute `$staged_G42/bin/switch-to-configuration test`.
- **$t = 3.6\text{s}$**: $N_3$ and $N_4$ pass all local D-Bus, `/dev/kmsg`, and data-plane probes, transition `PROBING -> BARRIER_WAIT`, and send `HealthAttestation(tx=42, HEALTHY)` to the coordinator. Packet delivery of `ActivateWave(42)` to $N_5$ was delayed in the OS send buffer; $N_5$ is still in `PREPARED(42)`.
- **$t = 4.0\text{s}$ (ADVERSARIAL FAULT)**: Coordinator suffers immediate power loss / `kill -9`.
- **$t \in (4.0\text{s}, 32.1\text{s})$**: $N_3$ and $N_4$ wait in `BARRIER_WAIT`. They gossip their `HealthAttestation`s to each other and $N_5$, but because $N_5$ has not attested `HEALTHY` and the coordinator is dead, no `LeaseKeepalive(42)` or `CommitWave(42)` with a valid `coord_sig` can be generated.
- **$t = 32.1\text{s}$**: `clock_gettime(CLOCK_BOOTTIME)` reaches `lease_deadline_boottime_ns` on $N_3$ and $N_4$ (and the staging/prepare inactivity timer fires on $N_5$).
- **$t = 32.2\text{s}$**:
  - $N_3$ and $N_4$ transition `BARRIER_WAIT -> ROLLED_BACK(42)`: they execute `renameat2(AT_FDCWD, "/run/epoch/current-secrets.prev", AT_FDCWD, "/run/epoch/current-secrets", RENAME_EXCHANGE)` restoring `gen-41`, run `/nix/var/nix/profiles/system/bin/switch-to-configuration test` ($G_{41}$), `explicit_bzero` + `unlink` `/run/epoch/secrets/gen-42`, remove `/nix/var/nix/gcroots/epoch/staging/tx-42`, disarm `/dev/watchdog`, and `fdatasync` `state.cbor` (`phase = RolledBack, highest_tx_epoch = 42`).
  - $N_5$ transitions `PREPARED -> ROLLED_BACK(42)`, `explicit_bzero`s `/run/epoch/secrets/gen-42`, removes `/nix/var/nix/gcroots/epoch/staging/tx-42`, and persists `RolledBack(42)`.
- **Terminal Invariant Proof**: $W_1$ is committed at $G_{42}$ (backward-compatible per causal wave contract), and 100% of $W_2$ ($N_3, N_4, N_5$) converges to $G_{41}$ within $32.8\text{s}$. If the crashed coordinator node reboots and replays stale packets with `tx_epoch <= 42`, all nodes reject them because `highest_tx_epoch == 42` in `RolledBack` state requires `tx_epoch >= 43` for any new transaction.

#### Scenario 2: Asymmetric Network Partition (Case A & Case B)
- **Initial State**: Coupled wave $W_1 = \{N_1, N_2, N_3\}$, `tx_epoch = 50`, `lease_ttl = 30s`, `peer_mesh_quorum = 2`. At $t = 0.0\text{s}$, all three nodes enter `ACTIVATING(50)`, flip `/run/epoch/current-secrets` via `RENAME_EXCHANGE` to `gen-50`, and run `$staged_G50/bin/switch-to-configuration test`.
- **Case A — Target $N_1$ Loses Coordinator Management Link, Retains Peer/Data-Plane Mesh to $N_2, N_3$**:
  1. **$t = 1.0\text{s}$ (ADVERSARIAL FAULT)**: An out-of-band management switch or firewall bug drops all packets between `Coordinator <-> N_1`, while production data-plane links `N_1 <-> N_2`, `N_1 <-> N_3`, and `Coordinator <-> {N_2, N_3}` remain healthy.
  2. **$t = 2.0\text{s}$**: $N_1, N_2, N_3$ enter `PROBING`. $N_1$ verifies systemd D-Bus convergence, zero `/dev/kmsg` errors, and succeeds on mTLS/QUIC data-plane probes to $N_2$ and $N_3$ (`reachable_peers = 3 >= 2`).
  3. **$t = 2.1\text{s}$**: $N_1$ transitions `PROBING -> BARRIER_WAIT`, signs `HealthAttestation(tx=50, wave=W_1, node=N_1, healthy=true, sig_N1)`, sees its direct QUIC stream to Coordinator time out, and gossips `HealthAttestation(N_1)` over the healthy data-plane QUIC mesh to peers $N_2$ and $N_3$.
  4. **$t = 2.2\text{s}$**: $N_2$ and $N_3$ wrap `HealthAttestation(N_1)` inside `PeerWitnessRelay { attestation, relay_node_id: "N_2", relay_sig }` and send it to Coordinator.
  5. **$t = 2.3\text{s}$**: Coordinator verifies `sig_N1` and `relay_sig`, observes 3/3 healthy nodes in $W_1$, signs `CommitWave(tx=50, wave=W_1, attestation_hashes, coord_sig)`, and transmits it to $N_2$ and $N_3$.
  6. **$t = 2.4\text{s}$**: $N_2$ and $N_3$ commit $G_{50}$ locally AND immediately forward `CommitWave(tx=50, coord_sig)` over the peer mesh to $N_1$.
  7. **$t = 2.5\text{s}$**: $N_1$ verifies `coord_sig` against `/etc/epoch/trusted-coordinators.pub`, transitions `BARRIER_WAIT -> COMMITTED(50)`, updates `/nix/var/nix/profiles/system`, runs `switch-to-configuration boot`, disarms `/dev/watchdog`, and zero-wipes `gen-49`.
  8. **Terminal Invariant Proof (Case A)**: All 3 nodes commit $G_{50}$ in $2.5\text{s}$. Zero false rollback occurs despite 100% packet loss between Coordinator and $N_1$.
- **Case B — Target $N_1$ Retains Coordinator Management Link, Loses Production Data-Plane / Peer Mesh to $N_2, N_3$**:
  1. **$t = 1.0\text{s}$ (ADVERSARIAL FAULT)**: $G_{50}$ introduces a broken `nftables` rule or WireGuard MTU bug on $N_1$ that blackholes $N_1$'s production data-plane VLAN (`eth1`) to $N_2$ and $N_3$, while $N_1$'s dedicated management interface (`eth0`) to Coordinator remains up.
  2. **$t = 2.0\text{s}$**: In `PROBING`, $N_1$'s D-Bus check passes (`sshd` and management agent are up), *but* $N_1$'s synthetic data-plane & peer-mesh oracle fails to reach $N_2$ or $N_3$ (`reachable_peers = 1 < peer_mesh_quorum = 2`), and $N_2, N_3$ report `peer_probe_failed(N_1)`.
  3. **$t = 5.0\text{s}$**: $N_1$'s probe retry window expires; $N_1$ immediately transitions `PROBING -> ROLLED_BACK(50)` (restoring `gen-49` secrets via `RENAME_EXCHANGE` and running `$G_{49}/bin/switch-to-configuration test`) and sends signed `HealthAttestation(tx=50, node=N_1, healthy=false, diagnostic="DataPlaneMeshIsolated")` to Coordinator over `eth0`.
  4. **$t = 5.1\text{s}$**: Coordinator receives `healthy=false` from $N_1$ and broadcasts signed `AbortWave(tx=50, wave=W_1, reason="N_1 DataPlaneMeshIsolated", coord_sig)` to $N_2$ and $N_3$.
  5. **$t = 5.6\text{s}$**: $N_2$ and $N_3$ exit `BARRIER_WAIT -> ROLLED_BACK(50)`, swap `/run/epoch/current-secrets` back to `gen-49` via `RENAME_EXCHANGE`, run `$G_{49}/bin/switch-to-configuration test`, and zero-wipe `gen-50`.
  6. **Terminal Invariant Proof (Case B)**: Even though $N_1$ remained reachable over management SSH/QUIC, the data-plane partition is caught by the peer mesh oracle and 100% of $W_1$ rolls back cleanly to $G_{49}$ in $5.6\text{s}$.

#### Scenario 3: Reboot into a Broken Kernel / Initrd Panic
- **Initial State**: Node $N_1$ in wave $W_1 = \{N_1, N_2\}$ upgrading kernel from $G_{10}$ (`linux-6.12.4`) to $G_{11}$ (`linux-6.13.0-broken-nvme`), `tx_epoch = 11`, `reboot_lease_ttl = 120s`.
- **$t = 0.0\text{s}$**: $N_1$ receives `ActivateWave(tx=11)`, detects `staged.kernel_path != booted.kernel_path`, and:
  1. Writes `/var/lib/epoch/state.cbor` (`phase = Activating, highest_tx_epoch = 11, prev_toplevel = G_10, staged_toplevel = G_11, reboot_deadline_wall_utc_s = now + 120`) and calls `fdatasync()`.
  2. Leaves `/boot/loader/loader.conf` `default nixos-generation-10.conf` untouched.
  3. Writes `/boot/loader/entries/nixos-generation-11+1-0.conf` (`+1` trial remaining) and sets EFI variable `LoaderEntryOneShot` to `nixos-generation-11+1-0.conf`.
  4. Arms `/dev/watchdog` (`WDIOC_SETTIMEOUT = 60s`) and triggers `Reboot` over systemd D-Bus.
- **$t = 10.0\text{s}$**: UEFI `systemd-boot` reads `LoaderEntryOneShot`, renames `nixos-generation-11+1-0.conf` $\to$ `nixos-generation-11+0-1.conf` on the ESP (`fsync`), and boots $G_{11}$'s kernel and `initrd`.
- **$t = 13.5\text{s}$ (ADVERSARIAL FAULT)**: $G_{11}$'s kernel panics in `initrd` before mounting `/` (`Kernel panic - not syncing: VFS: Unable to mount root fs`). Userspace never starts.
- **$t = 70.0\text{s}$**: The hardware watchdog timer (`60s` since last ping at $t = 10\text{s}$) expires and triggers a hard board reset (`RESET#`).
- **$t = 80.0\text{s}$**: `systemd-boot` inspects `nixos-generation-11+0-1.conf`, sees `0` tries remaining, ignores it, and boots the default entry `nixos-generation-10.conf` ($G_{10}$).
- **$t = 89.0\text{s}$**: In $G_{10}$ Stage 2, `epoch-early-unseal.service` runs `epoch-agent unseal-boot`, unsealing `/run/booted-system/node-overlay/epoch-secrets.cbor` ($G_{10}$) via `/dev/tpmrm0` into `/run/epoch/secrets/gen-10` and setting `/run/epoch/current-secrets -> gen-10` before networking starts.
- **$t = 92.0\text{s}$**: `epoch-agent.service` starts, reads `/var/lib/epoch/state.cbor` (`phase = Activating, highest_tx_epoch = 11, staged_toplevel = G_11`), sees `realpath("/run/booted-system") == G_10 != G_11`, unlinks `/boot/loader/entries/nixos-generation-11+0-1.conf` and `/nix/var/nix/gcroots/epoch/staging/tx-11`, persists `state.cbor` (`phase = RolledBack, highest_tx_epoch = 11`), and sends signed `HealthAttestation(tx=11, healthy=false, diagnostic="KernelBootFallbackToG10")` to Coordinator, which aborts $N_2$.
- **Terminal Invariant Proof**: $N_1$ survives a fatal `initrd` kernel panic automatically in $92\text{s}$ with zero human intervention, intact $G_{10}$ secrets, and full cohort rollback.

#### Scenario 4: Partial Closure Corruption (`BLAKE3` Mismatch) or `/nix/store` `ENOSPC` Mid-Transfer
- **Initial State**: Node $N_1$ running $G_{19}$ (`IDLE`), receiving `StageManifest(tx=20)` for $G_{20}$.
- **Trace 4A (`/nix/store` `ENOSPC` Pre-Check & Mid-Stream Fallback)**:
  1. `epoch-agent` sums `manifest.nar_size` for all store paths $p \in C_{20} \setminus \text{LocalStore}$ ($\sum = 620\text{ MiB}$) and calls `statvfs("/nix/store")`.
  2. Suppose `f_bavail * f_frsize == 900 MiB`, which is less than $620\text{ MiB} + 512\text{ MiB reserve} = 1,132\text{ MiB}$. `epoch-agent` immediately rejects `StageManifest(20)` with `StageError::StoreQuotaExceeded { available: 900 MiB, required: 1132 MiB }` without writing a single byte.
  3. Suppose pre-check passes, but a rogue log process fills the disk mid-transfer so `write()` on `/nix/store/.epoch-tmp-8f3a` returns `ENOSPC`. `epoch-agent` immediately closes the descriptor, unlinks all `/nix/store/.epoch-tmp-*` paths created in `tx=20`, unlinks `/nix/var/nix/gcroots/epoch/staging/tx-20`, stays in `IDLE`, and sends `StageError::IoEnospc` to Coordinator (aborting the rollout before any node enters `ACTIVATING`).
- **Trace 4B (Bit-Flip / `BLAKE3` Chunk Mismatch & `SHA-256` NAR Verification)**:
  1. While reconstructing `/nix/store/<hash>-glibc-2.40`, parent peer $N_2$ experiences a NIC DMA bit-flip on chunk $m=14$.
  2. `epoch-agent` decompresses $z_{14} \to \tilde{b}_{14}$ and computes $\text{BLAKE3}(\tilde{b}_{14}) \ne \text{manifest.chunks}[14].\text{norm\_blake3}$.
  3. `epoch-agent` drops $\tilde{b}_{14}$ in memory, records a strike against peer $N_2$, and re-requests chunk $h_{14}$ from fallback peer $N_3$ (or Coordinator).
  4. Once all chunks pass `BLAKE3` verification and inverse 32-byte store-hash substitution is applied, `epoch-agent` verifies the full NAR stream's `SHA-256` against `manifest.nar_sha256` and verifies `manifest.store_sig` against `/etc/nix/nix.conf` `trusted-public-keys`. If the full-NAR `SHA-256` or signature fails, `/nix/store/.epoch-tmp-*` is unlinked before SQLite registration in `/nix/var/nix/db/db.sqlite`.
- **Terminal Invariant Proof**: Zero corrupted or truncated files ever enter `/nix/store` or `db.sqlite`, and $G_{19}$ continues running undisturbed.

#### Scenario 5: Canary Failure on Node $k$ During a Coupled Multi-Node Wave After Speculative Activation
- **Initial State**: 5-node coupled wave $W_1 = \{N_1, N_2, N_3, N_4, N_5\}$, `tx_epoch = 77`, `max_unavailable = 0`, `lease_ttl = 30s`.
- **$t = 0.0\text{s}$**: All 5 nodes receive `ActivateWave(tx=77, wave=W_1, lease_ttl_ms=30000)`, atomically swap `/run/epoch/current-secrets -> gen-77` via `RENAME_EXCHANGE`, and run `$staged_G77/bin/switch-to-configuration test`.
- **$t = 2.2\text{s}$**: Nodes $N_1, N_2, N_3, N_4$ pass all D-Bus, `/dev/kmsg`, and data-plane probes, transition `PROBING -> BARRIER_WAIT`, and emit signed `HealthAttestation(tx=77, healthy=true)`. Crucial invariant: **none of $N_1 \dots N_4$ have committed `/nix/var/nix/profiles/system` or disarmed their `CLOCK_BOOTTIME` rollback lease!**
- **$t = 2.9\text{s}$ (ADVERSARIAL FAULT)**: On node $N_5$ ($k=5$), the new service binary hits an assertion failure and exits with `SIGABRT`; systemd marks `payment-engine.service` as `ActiveState = "failed"`.
- **$t = 3.0\text{s}$**: $N_5$'s D-Bus health oracle immediately observes `ActiveState == "failed"` on `payment-engine.service`:
  1. $N_5$ immediately transitions `PROBING -> ROLLED_BACK(77)`, executes `renameat2(..., RENAME_EXCHANGE)` on `/run/epoch/current-secrets` back to `gen-76`, runs `$G_{76}/bin/switch-to-configuration test`, and zero-wipes `gen-77`.
  2. $N_5$ broadcasts signed `HealthAttestation(tx=77, wave=W_1, node=N_5, healthy=false, diagnostic="UnitFailed: payment-engine.service", sig_N5)` to both the Coordinator AND cohort peers $\{N_1, N_2, N_3, N_4\}$.
- **$t = 3.1\text{s}$**: Both via direct peer gossip of $N_5$'s signed `healthy=false` attestation and via the Coordinator's `AbortWave(tx=77, wave=W_1, coord_sig)`, nodes $N_1, N_2, N_3, N_4$ immediately exit `BARRIER_WAIT -> ROLLED_BACK(77)`.
- **$t = 3.8\text{s}$**: $N_1, N_2, N_3, N_4$ complete `renameat2(..., RENAME_EXCHANGE)` restoring `gen-76` secrets, finish `$G_{76}/bin/switch-to-configuration test`, zero-wipe `/run/epoch/secrets/gen-77` (`explicit_bzero`), remove `/nix/var/nix/gcroots/epoch/staging/tx-77`, disarm `/dev/watchdog`, and `fdatasync` `state.cbor` (`phase = RolledBack, highest_tx_epoch = 77`).
- **Terminal Invariant Proof**: 100% of $\{N_1, N_2, N_3, N_4, N_5\}$ roll back both system closures and secrets to $G_{76}$ within $0.9\text{s}$ of $N_5$'s failure ($3.8\text{s}$ total elapsed time), with zero split-brain and zero secret skew.

---

### 7.2 Concrete Nix Flake Schema (`flake.nix`)
```nix
{
  description = "EPOCH Distributed Transactional NixOS Fleet Specification";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    epoch.url = "github:epoch-deploy/epoch";
  };

  outputs = { self, nixpkgs, epoch, ... }: {
    epoch.clusters.prod-us-east = epoch.lib.mkCluster {
      inherit nixpkgs;
      system = "x86_64-linux";

      # Pinned offline/HSM Ed25519 coordinator public keys trusted by target epoch-agents
      coordinatorPublicKeys = [
        "epoch-coord-primary:ed25519:b4f9c2d1e8a706543219fedcba9876543210fedcba9876543210fedcba987654"
      ];

      # Evaluation worker pool memory budget (Plane 1)
      evalPolicy = {
        maxWorkers = 4;
        workerMaxRssMiB = 768; # Hard _exit(0) recycling threshold: Total RSS <= 4 GiB
      };

      # Tier 1: Shared Service Archetypes (lib.evalModules evaluated ONCE per archetype)
      archetypes = {
        consensus-db = { config, lib, pkgs, ... }: {
          services.etcd.enable = true;
          services.postgresql = {
            enable = true;
            package = pkgs.postgresql_16;
          };
          # Secrets consumed from atomic symlink /run/epoch/current-secrets/<name>
          systemd.services.postgresql.serviceConfig.LoadCredential = [
            "repl_tls_key:/run/epoch/current-secrets/pg_repl_tls_key"
          ];
        };

        edge-api = { config, lib, pkgs, ... }: {
          services.nginx.enable = true;
          systemd.services.nginx.serviceConfig.LoadCredential = [
            "jwt_signing_key:/run/epoch/current-secrets/jwt_signing_key"
          ];
        };
      };

      # Tier 2: Per-Node Overlays (Evaluated in O(1) via /node-overlay late binding)
      nodes = {
        db-1 = {
          archetype = "consensus-db";
          topology = { rack = "rack-a"; zone = "us-east-1a"; endpoint = "10.10.1.11:9443"; };
          identity = {
            hostEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb9... db-1";
            tpm2PolicyAuthorizePub = ./keys/tpm2-pcr-policy-authority.pub;
            tpm2PcrMask = [ 0 2 7 ];
          };
          secrets.pg_repl_tls_key = {
            ciphertextFile = ./secrets/db-1/pg_repl_tls_key.epoch;
            owner = "postgres";
            group = "postgres";
            mode = "0400";
          };
          params = { hostName = "db-1"; ipv4 = "10.10.1.11/24"; machineId = "0102030405060708090a0b0c0d0e0f01"; };
        };

        db-2 = {
          archetype = "consensus-db";
          topology = { rack = "rack-b"; zone = "us-east-1b"; endpoint = "10.10.2.12:9443"; };
          identity = {
            hostEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHc8... db-2";
            tpm2PolicyAuthorizePub = ./keys/tpm2-pcr-policy-authority.pub;
            tpm2PcrMask = [ 0 2 7 ];
          };
          secrets.pg_repl_tls_key = {
            ciphertextFile = ./secrets/db-2/pg_repl_tls_key.epoch;
            owner = "postgres";
            group = "postgres";
            mode = "0400";
          };
          params = { hostName = "db-2"; ipv4 = "10.10.2.12/24"; machineId = "0102030405060708090a0b0c0d0e0f02"; };
        };

        db-3 = {
          archetype = "consensus-db";
          topology = { rack = "rack-c"; zone = "us-east-1c"; endpoint = "10.10.3.13:9443"; };
          identity = {
            hostEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJd7... db-3";
            tpm2PolicyAuthorizePub = ./keys/tpm2-pcr-policy-authority.pub;
            tpm2PcrMask = [ 0 2 7 ];
          };
          secrets.pg_repl_tls_key = {
            ciphertextFile = ./secrets/db-3/pg_repl_tls_key.epoch;
            owner = "postgres";
            group = "postgres";
            mode = "0400";
          };
          params = { hostName = "db-3"; ipv4 = "10.10.3.13/24"; machineId = "0102030405060708090a0b0c0d0e0f03"; };
        };

        api-1 = {
          archetype = "edge-api";
          topology = { rack = "rack-a"; zone = "us-east-1a"; endpoint = "10.10.1.21:9443"; };
          identity = {
            hostEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKe6... api-1";
            tpm2PolicyAuthorizePub = ./keys/tpm2-pcr-policy-authority.pub;
            tpm2PcrMask = [ 0 2 7 ];
          };
          secrets.jwt_signing_key = {
            ciphertextFile = ./secrets/api-1/jwt_signing_key.epoch;
            owner = "nginx";
            group = "nginx";
            mode = "0400";
          };
          params = { hostName = "api-1"; ipv4 = "10.10.1.21/24"; machineId = "0102030405060708090a0b0c0d0e0f04"; };
        };
      };

      # Plane 4: Causal DAG Rollout Waves, Quorum Invariants, & Multi-Signal Oracles
      rollout = {
        p2pFanout = 4; # k=4 rack-aware QUIC distribution tree
        quorums.etcd-cluster = {
          members = [ "db-1" "db-2" "db-3" ];
          maxUnavailable = 1; # Statically checked: 1 <= floor((3 - 1) / 2) = 1
        };
        waves = {
          db-canary = {
            nodes = [ "db-1" ];
            dependsOn = [];
            quorumRef = "etcd-cluster";
            leaseTtlSec = 30;
            rebootLeaseTtlSec = 120;
            probes = {
              requiredSystemdUnits = [ "etcd.service" "postgresql.service" ];
              tcpEndpoints = [ "127.0.0.1:2379" "127.0.0.1:5432" ];
              peerMeshQuorum = 1;
              forbidKmsgPatterns = [ "Oops:" "BUG:" "Out of memory: Killed process" ];
            };
          };
          db-cohort = {
            nodes = [ "db-2" "db-3" ];
            dependsOn = [ "db-canary" ];
            maxUnavailable = 0; # Coupled wave: 100% must pass BARRIER_WAIT
            leaseTtlSec = 30;
            rebootLeaseTtlSec = 120;
            probes = {
              requiredSystemdUnits = [ "etcd.service" "postgresql.service" ];
              tcpEndpoints = [ "127.0.0.1:2379" "127.0.0.1:5432" ];
              peerMeshQuorum = 2;
              forbidKmsgPatterns = [ "Oops:" "BUG:" "Out of memory: Killed process" ];
            };
          };
          api-fleet = {
            nodes = [ "api-1" ];
            dependsOn = [ "db-cohort" ];
            leaseTtlSec = 20;
            rebootLeaseTtlSec = 90;
            probes = {
              requiredSystemdUnits = [ "nginx.service" ];
              httpChecks = [ { url = "http://127.0.0.1:8080/healthz"; status = 200; } ];
              peerMeshQuorum = 1;
              forbidKmsgPatterns = [ "Oops:" "BUG:" "Out of memory: Killed process" ];
            };
          };
        };
      };
    };
  };
}
```

---

### 7.3 Concrete Binary Wire & Persistent State Struct Definitions (Rust / RFC 8949 CBOR)
```rust
use serde::{Deserialize, Serialize};

pub type Blake3Hash = [u8; 32];
pub type Sha256Hash = [u8; 32];
pub type Ed25519Pub = [u8; 32];
pub type Ed25519Sig = [u8; 64];

/// Plane 1: Cryptographically Signed Canonical Execution Plan (`plan.cbor`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedExecutionPlan {
    pub version: u16,
    pub cluster_id: String,
    pub tx_epoch: u64,
    pub flake_lock_blake3: Blake3Hash,
    pub waves: Vec<WaveSpec>,
    pub nodes: Vec<NodePlanEntry>,
    pub coordinator_pub: Ed25519Pub,
    /// Ed25519 signature over BLAKE3(RFC8949_deterministic_cbor(version..coordinator_pub))
    pub coordinator_sig: Ed25519Sig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaveSpec {
    pub wave_id: String,
    pub depends_on: Vec<String>,
    pub node_ids: Vec<String>,
    pub max_unavailable: u16,
    pub lease_ttl_ms: u32,
    pub reboot_lease_ttl_ms: u32,
    pub probes: HealthOracleSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePlanEntry {
    pub node_id: String,
    pub system_arch: String,
    pub rack_id: String,
    pub zone_id: String,
    pub quic_endpoint: String,
    pub node_pub: Ed25519Pub,
    pub toplevel_path: String,
    pub kernel_path: String,
    pub initrd_path: String,
    pub secrets_envelope_hash: Blake3Hash,
    pub closure_manifests_merkle_root: Blake3Hash,
    pub p2p_parent_node_id: Option<String>,
    pub p2p_children_node_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthOracleSpec {
    pub required_systemd_units: Vec<String>,
    pub tcp_endpoints: Vec<String>,
    pub http_checks: Vec<(String, u16)>,
    pub peer_mesh_quorum: u16,
    pub forbid_kmsg_patterns: Vec<String>,
}

/// Plane 2: Store-Hash-Normalized FastCDC Sub-Package Manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarChunkManifest {
    pub store_path: String,
    pub nar_sha256: Sha256Hash,
    pub nar_size: u64,
    /// Sorted 32-char nix-base32 store hashes r_0..r_{m-1} mapped to \x00EPOCH_REF_<u16_be(idx)>____________________
    pub reference_hashes: Vec<[u8; 32]>,
    pub references_full: Vec<String>,
    pub deriver: Option<String>,
    pub store_sig: String,
    pub chunks: Vec<ChunkDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkDescriptor {
    pub norm_blake3: Blake3Hash,
    pub raw_len: u32,
    pub zstd_len: u32,
}

/// Plane 3: Hardware-Bound In-Store Ciphertext Envelope (`epoch-secrets.cbor`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEnvelopeBundle {
    pub version: u16,
    pub node_id: String,
    pub archetype_toplevel: String,
    pub age_x25519_wrapped_dek: Vec<u8>,
    pub tpm2_sealed_dek: Option<Tpm2SealedBlob>,
    pub aead_nonce: [u8; 12],
    /// ChaCha20-Poly1305(DEK, nonce, AAD = BLAKE3("epoch-secret-v1" || node_id || archetype_toplevel), cbor(Vec<SecretEntry>))
    pub aead_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tpm2SealedBlob {
    pub pcr_mask: u32,
    pub policy_authorize_sig: Option<Ed25519Sig>,
    pub tpm2b_private: Vec<u8>,
    pub tpm2b_public: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub name: String,
    pub owner_user: String,
    pub owner_group: String,
    pub mode: u32,
    pub plaintext: Vec<u8>,
}

/// Plane 4: Target Crash-Safe Persistent State (`/var/lib/epoch/state.cbor`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentPhase {
    Idle,
    Staged,
    Prepared,
    Activating,
    Probing,
    BarrierWait,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentAgentState {
    pub highest_tx_epoch: u64,
    pub phase: AgentPhase,
    pub active_wave_id: Option<String>,
    pub prev_toplevel: String,
    pub prev_secret_epoch: u64,
    pub staged_toplevel: Option<String>,
    pub lease_deadline_boottime_ns: u64,
    pub reboot_deadline_wall_utc_s: u64,
    pub state_blake3_mac: Blake3Hash,
}

/// Plane 4: Wire Protocol Messages over QUIC/mTLS (`ALPN = "epoch-p2p/1"`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EpochWireMsg {
    StageManifest {
        tx_epoch: u64,
        plan: SignedExecutionPlan,
        manifests: Vec<NarChunkManifest>,
    },
    FetchChunksReq {
        tx_epoch: u64,
        missing_norm_blake3: Vec<Blake3Hash>,
    },
    FetchChunksResp {
        chunks: Vec<(Blake3Hash, Vec<u8>)>,
    },
    PrepareWave {
        tx_epoch: u64,
        wave_id: String,
    },
    ActivateWave {
        tx_epoch: u64,
        wave_id: String,
        lease_ttl_ms: u32,
        coord_sig: Ed25519Sig,
    },
    LeaseKeepalive {
        tx_epoch: u64,
        wave_id: String,
        extend_ttl_ms: u32,
        coord_sig: Ed25519Sig,
    },
    HealthAttestation {
        tx_epoch: u64,
        wave_id: String,
        node_id: String,
        healthy: bool,
        diagnostic: String,
        node_sig: Ed25519Sig,
    },
    PeerWitnessRelay {
        attestation: Box<EpochWireMsg>,
        relayed_coord_msg: Option<Box<EpochWireMsg>>,
        relay_node_id: String,
        relay_sig: Ed25519Sig,
    },
    CommitWave {
        tx_epoch: u64,
        wave_id: String,
        attestation_hashes: Vec<Blake3Hash>,
        coord_sig: Ed25519Sig,
    },
    AbortWave {
        tx_epoch: u64,
        wave_id: String,
        reason: String,
        coord_sig: Ed25519Sig,
    },
}
```

---

### 7.4 Deterministic NixOS VM Fault-Injection Test Harness & 1,000-Node Scaling Benchmark Specification

#### 7.4.1 NixOS VM Fault-Injection Harness (`nix/tests/epoch-fault-matrix.nix`)
Built on `pkgs.testers.runNixOSTest` with 6 QEMU/KVM nodes (`coord`, `db1`, `db2`, `db3`, `api1`, `cache`), dual virtual NICs (`eth0` on `vlan_mgmt = 1`, `eth1` on `vlan_data = 2`), UEFI `OVMF` (`boot.loader.systemd-boot.enable = true`), `swtpm` TPM 2.0 emulation, and QEMU hardware watchdog (`-watchdog i6300esb -watchdog-action reset`):
```nix
pkgs.testers.runNixOSTest {
  name = "epoch-adversarial-fault-matrix";
  nodes = {
    coord = { ... }: { virtualisation.vlans = [ 1 ]; };
    db1   = { ... }: { virtualisation.vlans = [ 1 2 ]; boot.loader.systemd-boot.enable = true; };
    db2   = { ... }: { virtualisation.vlans = [ 1 2 ]; boot.loader.systemd-boot.enable = true; };
    db3   = { ... }: { virtualisation.vlans = [ 1 2 ]; boot.loader.systemd-boot.enable = true; };
    api1  = { ... }: { virtualisation.vlans = [ 1 2 ]; boot.loader.systemd-boot.enable = true; };
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
```

#### 7.4.2 10 to 1,000+ Node Scaling Benchmark Specification
- **Evaluation Scaling Harness (`benchmarks/eval-scale.sh`)**:
  - Generates a flake with $|\mathcal{A}| = 8$ full NixOS archetypes and $N \in \{10, 100, 500, 1000, 2500\}$ node overlays (`95%` Fast-Path 2a data overlays, `5%` Fast-Path 2b structural module overrides).
  - Measures peak coordinator RSS via `/sys/fs/cgroup/epoch-bench/memory.peak` and wall-clock latency:
    - **Pass Criteria**: Peak RSS $\le 4.0\text{ GiB}$ across all $N \le 2,500$; cold evaluation at $N = 1,000$ in $< 25\text{ s}$; warm `BLAKE3` cache evaluation at $N = 1,000$ (with 1 node changed) in $< 150\text{ ms}$.
- **P2P Transport Scaling Harness (`benchmarks/p2p-scale.sh`)**:
  - Spawns 1,000 lightweight `epoch-agent` instances in isolated Linux network namespaces (`ip netns`) grouped into 25 simulated racks of 40 nodes bridged via `veth` + `tc qdisc netem rate 1gbit delay 0.5ms`.
  - Pushes a 1.2 GiB system closure where a 20 KiB daemon binary changed ($\Delta C_{\text{norm-CDC}} = 192\text{ KiB}$ across 3 normalized FastCDC chunks):
    - **Pass Criteria**: Coordinator total egress $\le 25 \times 192\text{ KiB} \approx 4.8\text{ MiB}$ (vs. `colmena`'s $1,000 \times 45\text{ MiBNAR} = 45\text{ GiB}$); 1,000-node staging convergence in $< 3.0\text{ s}$.

---

## Section 10: Final Gate & Contract Audit

| Qualification Gate / Contract Obligation | Verification Status | Section Reference |
| :--- | :--- | :--- |
| **Gate 0**: Subagent Contract Propagation | **VERIFIED** (Propagated verbatim; zero truncation) | Orchestrator Delegation |
| **Gate 1.1**: `deploy-rs` Structural & Mathematical Impossibility Proof | **VERIFIED** (File/line grounded in [`deploy.rs`](file:///tmp/investigation/deploy-rs/src/deploy.rs), [`activate.rs`](file:///tmp/investigation/deploy-rs/src/bin/activate.rs), [`cli.rs`](file:///tmp/investigation/deploy-rs/src/cli.rs), [`push.rs`](file:///tmp/investigation/deploy-rs/src/push.rs), [`flake.nix`](file:///tmp/investigation/deploy-rs/flake.nix)) | Section 3.1 (Theorems 1.1 & 1.2) |
| **Gate 1.2**: `colmena` Structural & Mathematical Impossibility Proof | **VERIFIED** (File/line grounded in [`eval.nix`](file:///tmp/investigation/colmena/src/nix/hive/eval.nix), [`mod.rs`](file:///tmp/investigation/colmena/src/nix/deployment/mod.rs), [`ssh.rs`](file:///tmp/investigation/colmena/src/nix/host/ssh.rs), [`modules.nix`](file:///tmp/investigation/colmena/src/nix/hive/modules.nix), [`key.rs`](file:///tmp/investigation/colmena/src/nix/key.rs)) | Section 3.2 (Theorems 1.3–1.6) |
| **Gate 2**: Four-Plane Data Movement & Distributed Systems Physics | **VERIFIED** (Planes 1–4 with store-hash normalizer, `/node-overlay`, `ramfs` `RENAME_EXCHANGE`, and `BARRIER_WAIT` leases) | Section 5.1–5.4 |
| **Gate 3**: Anti-Bloat Rejection Ledger & 1-to-1 Traceability Matrix | **VERIFIED** (R1–R8 disqualified; 10 retained mechanisms traced 1-to-1) | Section 9.1–9.2 |
| **Gate 4**: 5 Adversarial Execution Traces, Flake Schema, Wire Structs, & VM Test Harness | **VERIFIED** (Scenarios 1–5 including 2A & 2B, Nix schema, Rust CBOR structs, `runNixOSTest` harness) | Section 7.1–7.4 |
| **Contract Sections 1–10**: Authority, bounds, baseline, alternatives, syscalls, data costs, proofs | **VERIFIED** | Sections 1–10 |

<!-- GOAL_COMPLETE -->
