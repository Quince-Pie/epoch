{
  description = "Native Rust toolchains with declarative +toolchain selection";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Unstable no longer supports Intel macOS; 26.05 still does.
    nixpkgs-intel-darwin.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";

    # Dated URLs remain fetchable after the moving channel manifest changes.
    # Every rust-NAME input automatically provides +NAME. Use complete releases.
    rust-stable = {
      url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
      flake = false;
    };
  };

  outputs =
    inputs@{ nixpkgs, nixpkgs-intel-darwin, ... }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = lib.genAttrs systems;
      defaultToolchain = "stable";

      # Shared, lazy parsing: no manifest fetch or parsing at command invocation.
      manifests = lib.mapAttrs' (
        name: input:
        lib.nameValuePair (lib.removePrefix "rust-" name) (builtins.fromTOML (builtins.readFile input))
      ) (lib.filterAttrs (name: _: lib.hasPrefix "rust-" name) inputs);

      componentNames = [
        "rustc"
        "cargo"
        "rust-std"
        "rust-analyzer-preview"
        "clippy-preview"
        "rustfmt-preview"
        "rust-src"
      ];
      binaries = [
        "cargo"
        "rustc"
        "rustfmt"
        "cargo-fmt"
        "clippy-driver"
        "cargo-clippy"
        "rustdoc"
        "rust-analyzer"
      ];

      mkRustToolchain =
        pkgs: name: manifest:
        let
          hostTarget = pkgs.stdenv.hostPlatform.rust.rustcTarget;
          probeLegacyClippy = lib.versionOlder (lib.versions.majorMinor (
            manifest.pkg.rustc.version or "1.68"
          )) "1.68";
          getComponent =
            component:
            let
              target = if component == "rust-src" then "*" else hostTarget;
              data = manifest.pkg.${component}.target.${target} or { };
            in
            if data.available or false then
              pkgs.fetchurl {
                url = data.xz_url;
                sha256 = data.xz_hash;
              }
            else
              throw "Rust toolchain '${name}' (${manifest.date}) lacks required component '${component}' for '${target}'; pin a complete release.";
        in
        assert lib.assertMsg (
          builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" name != null
        ) "Invalid Rust toolchain name '${name}'.";
        assert lib.assertMsg (
          (manifest.manifest-version or null) == "2"
        ) "Rust toolchain '${name}' requires a version 2 distribution manifest.";
        pkgs.stdenvNoCC.mkDerivation (
          {
            # Aliases for identical manifests share the same installation.
            pname = "rust-toolchain";
            version = manifest.date;
            srcs = map getComponent componentNames;
            sourceRoot = ".";
            strictDeps = true;
            dontConfigure = true;
            dontBuild = true;
            # Stripping upstream rlibs can destroy their Rust metadata.
            dontStrip = true;
            nativeBuildInputs = lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.autoPatchelfHook;
            buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.stdenv.cc.cc.lib
              pkgs.zlib
            ];

            # Missing ELF dependencies are errors. No LD_LIBRARY_PATH workaround
            # is needed to run a realized toolchain outside the development shell.
            installPhase = ''
              runHook preInstall
              for installer in */install.sh; do
                if [[ -d "''${installer%/install.sh}/rust-src" ]]; then
                  bash ${./nix/batch-rust-src.sh} "''${installer%/install.sh}" "$out"
                fi
                # Upstream can mask a failed copy with a successful chmod.
                bash -e "$installer" --prefix="$out" --disable-ldconfig
              done
              rm -rf "$out/share/doc/rust"
              rm -f "$out/lib/rustlib/"{components,install.log,uninstall.sh,rust-installer-version,manifest-*}
              for binary in ${lib.escapeShellArgs binaries}; do
                test -x "$out/bin/$binary"
              done
              test -f "$out/lib/rustlib/src/rust/library/core/src/lib.rs"
              test -d "$out/lib/rustlib/${hostTarget}/lib"
              runHook postInstall
            '';
            meta.platforms = systems;
          }
          // lib.optionalAttrs probeLegacyClippy {
            # Clippy before 1.67 inferred a rustup sysroot from the selector.
            # Include the 1.67 nightly transition, then probe the actual behavior.
            postInstall = ''
              fixLegacyClippySysroot() {
                local probe_home="$out/.clippy-sysroot-probe" probe
                probe=$(env -u SYSROOT RUSTUP_HOME="$probe_home" RUSTUP_TOOLCHAIN=probe \
                  "$out/bin/clippy-driver" --print sysroot)
                if [[ "$probe" == "$probe_home/toolchains/probe" ]]; then
                  mv "$out/bin/clippy-driver" "$out/bin/.clippy-driver-unwrapped"
                  cat > "$out/bin/clippy-driver" <<EOF
              #!${pkgs.runtimeShell}
              export SYSROOT="\''${SYSROOT-$out}"
              exec "$out/bin/.clippy-driver-unwrapped" "\$@"
              EOF
                  chmod +x "$out/bin/clippy-driver"
                elif [[ "$probe" != "$out" ]]; then
                  printf 'Unexpected Clippy sysroot: %s\n' "$probe" >&2
                  return 1
                fi
                test "$(env -u SYSROOT RUSTUP_HOME="$probe_home" RUSTUP_TOOLCHAIN=probe \
                  "$out/bin/clippy-driver" --print sysroot)" = "$out"
              }
              # Setup hooks already registered autoPatchelf, which must run first.
              postFixupHooks+=(fixLegacyClippySysroot)
            '';
          }
        );

      mkRustupProxy =
        pkgs: toolchains:
        assert lib.assertMsg (builtins.hasAttr defaultToolchain toolchains)
          "The default Rust toolchain '${defaultToolchain}' must be configured.";
        pkgs.runCommand "rust-multiplexer"
          {
            passAsFile = [ "script" ];
            # Keep children on the selected compiler, as in the original proxy.
            # Bash suppresses splitting/globbing in assignments, [[ ]] and case;
            # printf data, the executable path, and forwarded arguments stay quoted.
            script = ''
              #!${pkgs.runtimeShell}
              if [[ ''${1-} == +* ]]; then
                toolchain=''${1#+}
                shift
              else
                toolchain=''${RUSTUP_TOOLCHAIN:-${defaultToolchain}}
              fi

              case $toolchain in
                ${lib.concatStringsSep "\n" (
                  lib.mapAttrsToList (name: path: ''
                    ${lib.escapeShellArg name}) toolchain_path=${lib.escapeShellArg (toString path)} ;;
                  '') toolchains
                )}
                *)
                  printf "error: Nix Flake environment does not provide toolchain '+%s'\n" "$toolchain" >&2
                  printf '%s\n' ${lib.escapeShellArg "Available configured toolchains: ${lib.concatStringsSep ", " (builtins.attrNames toolchains)}"} >&2
                  exit 1
                  ;;
              esac

              export RUSTUP_TOOLCHAIN=$toolchain \
                RUSTC=$toolchain_path/bin/rustc \
                RUSTDOC=$toolchain_path/bin/rustdoc \
                RUST_SRC_PATH=$toolchain_path/lib/rustlib/src/rust/library
              exec "$toolchain_path/bin/''${0##*/}" "$@"
            '';
            meta.mainProgram = "cargo";
          }
          ''
            ${pkgs.runtimeShell} -n "$scriptPath"
            install -Dm755 "$scriptPath" "$out/bin/cargo"
            for binary in ${lib.escapeShellArgs (lib.remove "cargo" binaries)}; do
              ln -s cargo "$out/bin/$binary"
            done
          '';

      perSystem = forAllSystems (
        system:
        let
          pkgs =
            (if system == "x86_64-darwin" then nixpkgs-intel-darwin else nixpkgs).legacyPackages.${system};
          toolchains = lib.mapAttrs (mkRustToolchain pkgs) manifests;
          proxy = mkRustupProxy pkgs toolchains;
          formatter = pkgs.nixfmt-tree.override {
            # Also find the project root in copies without Git metadata.
            settings.tree-root-file = "flake.nix";
          };
        in
        {
          inherit
            toolchains
            proxy
            formatter
            ;
          shell = pkgs.mkShell {
            packages = [
              proxy
              pkgs.pkg-config
              pkgs.cargo-watch
            ];
            buildInputs = [
              pkgs.openssl
              pkgs.zlib
              pkgs.zstd
              pkgs.sqlite
            ]
            ++ lib.optional pkgs.stdenv.hostPlatform.isDarwin pkgs.libiconv;

            # Retained for programs developed in the shell that load these libs.
            LD_LIBRARY_PATH = lib.optionalString pkgs.stdenv.hostPlatform.isLinux (
              lib.makeLibraryPath [
                pkgs.stdenv.cc.cc.lib
                pkgs.zlib
                pkgs.openssl
                pkgs.zstd
                pkgs.sqlite
              ]
            );

            shellHook = ''
              echo "=========================================================="
              echo " 🦀 Rustup-like Multiplexer (Pure Nix)"
              echo "=========================================================="
              ${lib.concatMapStrings (name: ''
                printf ' • %s (+%s): %s\n' ${
                  lib.escapeShellArgs [
                    name
                    name
                    manifests.${name}.date
                  ]
                }
              '') ([ defaultToolchain ] ++ lib.remove defaultToolchain (builtins.attrNames manifests))}
              echo "=========================================================="
              echo "Select a toolchain with cargo +NAME."
            '';
          };
        }
      );
      epochLib = import ./nix/lib.nix { inherit lib; };
    in
    {
      lib = epochLib;
      nixosModules = {
        default = ./nix/archetype-module.nix;
        epoch-archetype = ./nix/archetype-module.nix;
      };
      schemaTests = import ./nix/tests/schema-eval-test.nix {
        inherit nixpkgs epochLib;
      };
      devShells = forAllSystems (system: {
        default = perSystem.${system}.shell;
      });
      packages = forAllSystems (
        system:
        {
          default = perSystem.${system}.proxy;
        }
        // lib.mapAttrs' (
          name: value: lib.nameValuePair "rust-${name}" value
        ) perSystem.${system}.toolchains
      );
      formatter = forAllSystems (system: perSystem.${system}.formatter);
    };
}
