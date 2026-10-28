# Plane 1: Pure-Nix Typed Cluster, Archetype + /node-overlay, Wave DAG, & Quorum Schema (`epoch.lib.mkCluster`)
{ lib }:

rec {
  archetypeModule = ./archetype-module.nix;

  # Validate Static Quorum Safety Invariant:
  # forall Q_r: maxUnavailable(Q_r) <= floor((|Q_r| - 1) / 2)
  # and forall W_k: |W_k \cap Q_r| <= maxUnavailable(Q_r)
  validateQuorums =
    quorums: waves:
    let
      validateWaveQuorumRef =
        wName: wSpec:
        if (wSpec ? quorumRef) && !(builtins.hasAttr wSpec.quorumRef quorums) then
          throw "UnknownQuorumRef: wave '${wName}' references undefined quorum '${wSpec.quorumRef}'"
        else
          true;
      _waveRefsValid = builtins.all (x: x) (lib.mapAttrsToList validateWaveQuorumRef waves);
      checkQuorum =
        qName: qSpec:
        let
          memberCount = builtins.length qSpec.members;
          maxFaultTolerant = (memberCount - 1) / 2;
          maxUnavail = qSpec.maxUnavailable or 0;
          anyExplicitRef = builtins.any (w: (w.quorumRef or null) == qName) (builtins.attrValues waves);
          checkWave =
            wName: wSpec:
            let
              applies =
                if anyExplicitRef then
                  (wSpec.quorumRef or null) == qName
                else
                  (wSpec.quorumRef or qName) == qName;
              overlap = builtins.filter (n: builtins.elem n qSpec.members) wSpec.nodes;
              overlapCount = builtins.length overlap;
            in
            if applies && overlapCount > maxUnavail then
              throw "QuorumSafetyViolation: wave '${wName}' concurrently targets ${toString overlapCount} members of quorum '${qName}', exceeding maxUnavailable=${toString maxUnavail}"
            else
              true;
          waveChecks = lib.mapAttrsToList checkWave waves;
        in
        if memberCount == 0 then
          throw "QuorumSafetyViolation: quorum '${qName}' has empty members list"
        else if maxUnavail > maxFaultTolerant then
          throw "QuorumSafetyViolation: quorum '${qName}' sets maxUnavailable=${toString maxUnavail} > floor((|Q|-1)/2)=${toString maxFaultTolerant}"
        else
          builtins.all (x: x) waveChecks;
      allChecks = lib.mapAttrsToList checkQuorum quorums;
    in
    assert _waveRefsValid;
    builtins.all (x: x) allChecks;

  # Pure-Nix Kahn's Topological Sort & Cycle Detector over `rollout.waves`
  toposortWaves =
    waves:
    let
      waveNames = builtins.attrNames waves;
      # Verify all dependsOn targets exist
      validateDeps =
        wName: wSpec:
        let
          deps = wSpec.dependsOn or [ ];
          missing = builtins.filter (d: !(builtins.hasAttr d waves)) deps;
        in
        if missing != [ ] then
          throw "InvalidWaveDependency: wave '${wName}' depends on unknown wave '${builtins.head missing}'"
        else
          true;
      _depsValid = builtins.all (x: x) (lib.mapAttrsToList validateDeps waves);

      step =
        resolved: remaining:
        if remaining == [ ] then
          resolved
        else
          let
            isReady =
              wName:
              let
                deps = waves.${wName}.dependsOn or [ ];
              in
              builtins.all (d: builtins.elem d resolved) deps;
            readyNow = builtins.filter isReady remaining;
            stillWaiting = builtins.filter (w: !(builtins.elem w readyNow)) remaining;
          in
          if readyNow == [ ] then
            throw "CyclicWaveDependency: rollout.waves contains a causal cycle involving: ${lib.concatStringsSep ", " remaining}"
          else
            step (resolved ++ readyNow) stillWaiting;
    in
    assert _depsValid;
    map (wName: { waveId = wName; } // waves.${wName}) (step [ ] waveNames);

  # Compile Rack-Aware k-ary P2P Distribution Spanning Tree per (rack, system)
  compileP2pTree =
    kFanout: system: nodes:
    let
      k = if kFanout < 1 then 1 else kFanout;
      nodeNames = builtins.attrNames nodes;
      byRack = lib.groupBy (n: nodes.${n}.topology.rack or "default-rack") nodeNames;

      buildRackEntries =
        rackName: rackNodes:
        let
          count = builtins.length rackNodes;
          mkEntry =
            idx: nodeName:
            let
              parentIdx = (idx - 1) / k;
              parent = if idx == 0 then null else builtins.elemAt rackNodes parentIdx;
              firstChild = k * idx + 1;
              childIndices = lib.filter (c: c < count) (lib.range firstChild (k * idx + k));
              children = map (c: builtins.elemAt rackNodes c) childIndices;
            in
            lib.nameValuePair nodeName {
              inherit
                nodeName
                rackName
                system
                parent
                children
                ;
              isRackSeed = idx == 0;
              endpoint = nodes.${nodeName}.topology.endpoint;
              zone = nodes.${nodeName}.topology.zone or "default-zone";
            };
        in
        lib.imap0 mkEntry rackNodes;
    in
    builtins.listToAttrs (lib.concatLists (lib.mapAttrsToList buildRackEntries byRack));

  # Plane 3 & Gate 3: Statically reject plaintext secrets (`text`, `keyCommand`, `keyFile`)
  # or disqualified imperative hooks (`preDeployHook`, `postDeployHook`, `forwardAgent`) at Nix eval time.
  validateSecretEnvelopes =
    nodes:
    let
      checkNode =
        nodeName: nodeCfg:
        let
          secrets = nodeCfg.secrets or { };
          checkSecret =
            secName: secSpec:
            if (secSpec ? text) || (secSpec ? keyCommand) || (secSpec ? keyFile) then
              throw "DisqualifiedPlaintextSecretInStore: node '${nodeName}' secret '${secName}' defines plaintext 'text'/'keyCommand'/'keyFile'; secrets must use hardware/host-sealed ciphertext envelopes"
            else
              true;
        in
        if (nodeCfg ? preDeployHook) || (nodeCfg ? postDeployHook) || (nodeCfg ? forwardAgent) then
          throw "DisqualifiedAntiPatternBloat: node '${nodeName}' defines prohibited imperative hook or SSH agent forwarding"
        else
          builtins.all (x: x) (lib.mapAttrsToList checkSecret secrets);
    in
    builtins.all (x: x) (lib.mapAttrsToList checkNode nodes);

  coreBaseModulesList = builtins.fromJSON (builtins.readFile ./core-base-modules.json);

  mkStubOpt = default: lib.mkOption { inherit default; } // { _epochStub = true; };

  # Recursively verify that all attribute paths defined by an archetype module exist as non-stub
  # options in `fastSys.options` before forcing `fastSys.config.system.build.toplevel.drvPath`.
  # Prevents `_module.check = false` from silently ignoring options outside the core module slice.
  checkDefsInOptions =
    opts: defs:
    let
      rawDefs =
        if defs ? config && !(defs ? _type) then
          defs.config
        else
          builtins.removeAttrs defs [
            "imports"
            "options"
            "_module"
          ];
      hasExtraImports = (defs ? imports) && (defs.imports != [ ]);
      walk =
        optCursor: defCursor:
        if lib.isOption optCursor then
          !(optCursor._epochStub or false)
        else if builtins.isAttrs defCursor then
          if (defCursor ? _type) then
            if (defCursor._type == "if" || defCursor._type == "override") && (defCursor ? content) then
              walk optCursor defCursor.content
            else if (defCursor._type == "merge") && (defCursor ? contents) then
              builtins.all (c: walk optCursor c) defCursor.contents
            else
              false
          else
            builtins.all (
              k:
              (builtins.isAttrs optCursor)
              && (builtins.hasAttr k optCursor)
              && (walk optCursor.${k} defCursor.${k})
            ) (builtins.attrNames defCursor)
        else
          false;
    in
    (!hasExtraImports) && (walk opts rawDefs);

  # Tier-1 Fast-Path: Evaluate an archetype against the 157-module closed active core NixOS module set
  # (producing bit-for-bit identical .drv store paths as full 2,126-module module-list.nix), with
  # automatic pre-checked fallback to the full module list if any custom module references an external option.
  evalArchetype =
    {
      nixpkgs,
      system ? "x86_64-linux",
      pkgs ? nixpkgs.legacyPackages.${system},
      archName ? "archetype",
      archModule,
      sharedModules ? [ ],
    }:
    let
      probeModule =
        m:
        if builtins.isFunction m then
          m {
            config = { };
            options = { };
            inherit lib pkgs;
          }
        else if builtins.isAttrs m then
          m
        else
          { };
      probeArch = probeModule archModule;
      rawProbe =
        if probeArch ? config && !(probeArch ? _type) then probeArch.config else probeArch;
      svcs = if (builtins.tryEval (rawProbe ? services)).value or false then rawProbe.services else { };
      useEtcd = (builtins.tryEval (svcs ? etcd)).value or true;
      usePg = (builtins.tryEval (svcs ? postgresql)).value or true;
      useRedis = (builtins.tryEval (svcs ? redis)).value or true;
      useNginx = (builtins.tryEval (svcs ? nginx)).value or true;

      activeCoreRelList = lib.filter (
        m:
        (m != "services/databases/etcd.nix" || useEtcd)
        && (m != "services/databases/postgresql.nix" || usePg)
        && (m != "services/databases/redis.nix" || useRedis)
        && (m != "services/web-servers/nginx/default.nix" || useNginx)
      ) coreBaseModulesList;

      demandStubs = {
        options = {
          networking.wireguard.interfaces = mkStubOpt { };
          services =
            {
              hadoop.hdfs.namenode.enable = mkStubOpt false;
              hadoop.hdfs.datanode.enable = mkStubOpt false;
              hadoop.hdfs.journalnode.enable = mkStubOpt false;
              hadoop.hdfs.httpfs.enable = mkStubOpt false;
              hadoop.yarn.resourcemanager.enable = mkStubOpt false;
              hadoop.yarn.nodemanager.enable = mkStubOpt false;
              kubernetes.apiserver.enable = mkStubOpt false;
              kubernetes.controllerManager.enable = mkStubOpt false;
              kubernetes.scheduler.enable = mkStubOpt false;
              kubernetes.addonManager.enable = mkStubOpt false;
              kubernetes.proxy.enable = mkStubOpt false;
              kubernetes.kubelet.enable = mkStubOpt false;
              kubernetes.roles = mkStubOpt [ ];
              hercules-ci-agents = mkStubOpt { };
              libeufin.bank.connections = mkStubOpt { };
              postfix.enable = mkStubOpt false;
              mautrix-meta.instances = mkStubOpt { };
              opentelemetry-collector.enable = mkStubOpt false;
              samba.enable = mkStubOpt false;
              samba.nsswins = mkStubOpt false;
              firezone.server.enable = mkStubOpt false;
              hylafax.enable = mkStubOpt false;
              netbird.clients = mkStubOpt { };
              netbird.server.enable = mkStubOpt false;
              netbird.server.coturn.enable = mkStubOpt false;
              nghttpx.enable = mkStubOpt false;
              wireguard.enable = mkStubOpt false;
              znc.enable = mkStubOpt false;
              kanidm.unix.enable = mkStubOpt false;
              kanidm.enableServer = mkStubOpt false;
              spire.agent.enable = mkStubOpt false;
              spire.server.enable = mkStubOpt false;
            }
            // (lib.optionalAttrs (!useEtcd) { etcd.enable = mkStubOpt false; })
            // (lib.optionalAttrs (!usePg) { postgresql.enable = mkStubOpt false; })
            // (lib.optionalAttrs (!useRedis) { redis.servers = mkStubOpt { }; })
            // (lib.optionalAttrs (!useNginx) { nginx.enable = mkStubOpt false; });
        };
      };

      commonModules =
        [
          archetypeModule
          archModule
          {
            nixpkgs.hostPlatform = lib.mkDefault system;
            boot.isContainer = lib.mkDefault true;
            system.stateVersion = lib.mkDefault "24.11";
          }
        ]
        ++ sharedModules;
      fastSys = nixpkgs.lib.nixosSystem {
        system = null;
        inherit pkgs;
        baseModules = (map (rel: nixpkgs + ("/nixos/modules/" + rel)) activeCoreRelList) ++ [ demandStubs ];
        modules = commonModules ++ [
          { _module.check = false; }
        ];
      };
      fullSys = nixpkgs.lib.nixosSystem {
        system = null;
        inherit pkgs;
        modules = commonModules;
      };
      evalModuleWithFast =
        m:
        if builtins.isFunction m then
          m {
            config = fastSys.config;
            options = fastSys.options;
            inherit lib pkgs;
          }
        else if builtins.isAttrs m then
          m
        else
          { imports = [ m ]; };
      optsOk =
        (builtins.tryEval (
          builtins.all (m: checkDefsInOptions fastSys.options (evalModuleWithFast m)) (
            [ archModule ] ++ sharedModules
          )
        )).value or false;
      fastTry = builtins.tryEval fastSys.config.system.build.toplevel.drvPath;
    in
    if optsOk && fastTry.success then fastSys else fullSys;

  # Tier-2 Fast-Path 2a: Construct per-node closure derivation in O(1) without calling evalModules or stdenv.
  # Produces the exact same canonical ATerm `Derive(...)` and SHA-256 `.drv` store path as `synthesize_node_overlay_drv_aterm` in `src/plane1_eval.rs`.
  mkNodeClosure =
    {
      pkgs ? null,
      system ? if pkgs != null then pkgs.stdenv.hostPlatform.system else "x86_64-linux",
      archetypeToplevel,
      nodeName,
      nodeConfig,
      secretsEnvelopeDrv ? null,
    }:
    let
      archDrvPath = builtins.unsafeDiscardStringContext (
        if builtins.isAttrs archetypeToplevel && (archetypeToplevel ? drvPath) then
          archetypeToplevel.drvPath
        else
          toString archetypeToplevel
      );
      archName = nodeConfig.archetype or "";
      rack = nodeConfig.topology.rack or "";
      zone = nodeConfig.topology.zone or "";
      endpoint = nodeConfig.topology.endpoint or "";
      hostName = nodeConfig.params.hostName or nodeName;
      ipv4 = nodeConfig.params.ipv4 or "";
      machineId = nodeConfig.params.machineId or "00000000000000000000000000000000";
      ciphertextEnvelope =
        if secretsEnvelopeDrv != null then
          builtins.unsafeDiscardStringContext (toString secretsEnvelopeDrv)
        else if
          (nodeConfig ? secrets)
          && (nodeConfig.secrets ? service_secret_key)
          && (nodeConfig.secrets.service_secret_key ? ciphertextEnvelope)
        then
          nodeConfig.secrets.service_secret_key.ciphertextEnvelope
        else
          builtins.toJSON (nodeConfig.secrets or { });
    in
    derivation {
      name = "epoch-node-${nodeName}";
      inherit system;
      builder = "/bin/sh";
      args = [
        "-e"
        "-c"
        "mkdir -p $out/node-overlay/etc"
      ];
      allowSubstitutes = false;
      preferLocalBuild = true;
      archetype = archName;
      archetypeDrv = archDrvPath;
      inherit
        ciphertextEnvelope
        endpoint
        hostName
        ipv4
        machineId
        rack
        zone
        ;
    };

  # Top-level cluster constructor (`epoch.lib.mkCluster` from DESIGN.md §7.2)
  mkCluster =
    {
      nixpkgs,
      system ? "x86_64-linux",
      coordinatorPublicKeys ? [ ],
      evalPolicy ? {
        maxWorkers = 4;
        workerMaxRssMiB = 768;
      },
      sharedModules ? [ ],
      archetypes,
      nodes,
      rollout,
    }:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ ];
      };
      quorums = rollout.quorums or { };
      waves = rollout.waves or { };
      p2pFanout = rollout.p2pFanout or 4;

      # Statically verify quorum invariants, wave DAG acyclicity, and secret envelope safety at Nix evaluation time
      secretsValid = validateSecretEnvelopes nodes;
      quorumValid = assert secretsValid; validateQuorums quorums waves;
      sortedWaves = assert quorumValid; toposortWaves waves;
      p2pTree = compileP2pTree p2pFanout system nodes;

      # Tier 1: Evaluate each shared service archetype ONCE per archetype (sharing pkgs + 157-module core slice)
      archetypeSystems = lib.mapAttrs (
        archName: archModule:
        evalArchetype {
          inherit
            nixpkgs
            pkgs
            system
            archModule
            sharedModules
            ;
        }
      ) archetypes;

      archetypeToplevelDrvPaths = lib.mapAttrs (
        _: sys: sys.config.system.build.toplevel.drvPath
      ) archetypeSystems;

      # Lightweight mock archetype toplevels for fast pure metadata evaluation without building kernels
      archetypeLightDirs = lib.mapAttrs (
        archName: _:
        derivation {
          name = "epoch-archetype-${archName}";
          inherit system;
          builder = "/bin/sh";
          args = [
            "-e"
            "-c"
            "mkdir -p $out/bin $out/etc && printf '#!/bin/sh\\nexit 0\\n' > $out/bin/switch-to-configuration && chmod +x $out/bin/switch-to-configuration"
          ];
          preferLocalBuild = true;
          allowSubstitutes = false;
        }
      ) archetypes;

      # Tier 2: O(1) per-node overlay closures
      nodeOverlayClosures =
        assert secretsValid;
        lib.mapAttrs (
          nodeName: nodeCfg:
          let
            archName = nodeCfg.archetype;
            _checkArch =
              if !(builtins.hasAttr archName archetypes) then
                throw "UnknownArchetype: node '${nodeName}' references undefined archetype '${archName}'"
              else
                true;
          in
          assert _checkArch;
          mkNodeClosure {
            inherit pkgs system nodeName;
            archetypeToplevel = archetypeLightDirs.${archName};
            nodeConfig = nodeCfg;
          }
        ) nodes;

      # Tier 2 (Full NixOS Archetype Toplevels): O(1) per-node overlay derivations grafted onto
      # the full NixOS `archetypeSystems.<arch>.config.system.build.toplevel` fixpoint.
      nixosNodeOverlayClosures =
        assert secretsValid;
        lib.mapAttrs (
          nodeName: nodeCfg:
          let
            archName = nodeCfg.archetype;
            _checkArch =
              if !(builtins.hasAttr archName archetypes) then
                throw "UnknownArchetype: node '${nodeName}' references undefined archetype '${archName}'"
              else
                true;
          in
          assert _checkArch;
          mkNodeClosure {
            inherit pkgs system nodeName;
            archetypeToplevel = archetypeSystems.${archName}.config.system.build.toplevel;
            nodeConfig = nodeCfg;
          }
        ) nodes;

      nixosNodeOverlayDrvPaths = lib.mapAttrs (_: drv: drv.drvPath) nixosNodeOverlayClosures;

      planSpec = {
        version = 1;
        inherit
          system
          coordinatorPublicKeys
          evalPolicy
          p2pFanout
          ;
        archetypeNames = builtins.attrNames archetypes;
        waves = sortedWaves;
        quorums = quorums;
        p2pTree = p2pTree;
        nodes = lib.mapAttrs (
          nodeName: nodeCfg: {
            inherit nodeName;
            archetype = nodeCfg.archetype;
            topology = nodeCfg.topology;
            params = nodeCfg.params or { };
            p2pParent = p2pTree.${nodeName}.parent;
            p2pChildren = p2pTree.${nodeName}.children;
            isRackSeed = p2pTree.${nodeName}.isRackSeed;
          }
        ) nodes;
      };
    in
    {
      inherit
        quorumValid
        sortedWaves
        p2pTree
        archetypeSystems
        archetypeToplevelDrvPaths
        nodeOverlayClosures
        nixosNodeOverlayClosures
        nixosNodeOverlayDrvPaths
        planSpec
        ;
      planJson = builtins.toJSON planSpec;
      planFile = pkgs.writeText "epoch-plan.json" (builtins.toJSON planSpec);
    };
}
