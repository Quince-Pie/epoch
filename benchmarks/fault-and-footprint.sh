#!/usr/bin/env bash
# Plane 3 & Plane 4 Head-to-Head Benchmark:
# - Target Daemon Footprint (`epoch-agent` < 5 MiB binary, `mlockall`, `OOMScoreAdjust=-1000`)
# - Secret Swap Skew (`RENAME_EXCHANGE` vs `colmena` `src/nix/host/key_uploader.template.sh`)
# - Gate 4 Adversarial Fault-Injection Convergence Matrix (5 Fault Scenarios)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -x "$REPO_ROOT/target/release/epoch" ]; then
  EPOCH_BIN="${EPOCH_BIN:-$REPO_ROOT/target/release/epoch}"
else
  EPOCH_BIN="${EPOCH_BIN:-$REPO_ROOT/target/debug/epoch}"
fi

if [ ! -x "$EPOCH_BIN" ]; then
  nix develop "path:$REPO_ROOT" --command cargo build --release --offline --manifest-path "$REPO_ROOT/Cargo.toml"
  EPOCH_BIN="$REPO_ROOT/target/release/epoch"
fi

echo "========================================================================="
echo " PLANE 3 & PLANE 4: FOOTPRINT, SECRET SKEW, & GATE 4 FAULT BENCHMARK"
echo "========================================================================="
"$EPOCH_BIN" benchmark-plane34 \
  --colmena-key-template /tmp/investigation/colmena/src/nix/host/key_uploader.template.sh \
  --secret-rotations "${SECRET_ROTATIONS:-50}"
