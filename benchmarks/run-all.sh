#!/usr/bin/env bash
# Master Reproducible Head-to-Head Benchmark Runner: EPOCH vs. deploy-rs vs. colmena
# Executes Planes 1, 2, 3, and 4 benchmarks and writes structured JSON results to
# `/tmp/investigation/epoch/benchmarks/results/head-to-head-results.json`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

if [ -x "$REPO_ROOT/target/release/epoch" ]; then
  EPOCH_BIN="${EPOCH_BIN:-$REPO_ROOT/target/release/epoch}"
else
  EPOCH_BIN="${EPOCH_BIN:-$REPO_ROOT/target/debug/epoch}"
fi

if [ ! -x "$EPOCH_BIN" ]; then
  nix develop "path:$REPO_ROOT" --command cargo build --release --offline --manifest-path "$REPO_ROOT/Cargo.toml"
  EPOCH_BIN="$REPO_ROOT/target/release/epoch"
fi

OUT_JSON="${1:-$RESULTS_DIR/head-to-head-results.json}"

echo "========================================================================="
echo " RUNNING FULL HEAD-TO-HEAD BENCHMARK SUITE (EPOCH vs deploy-rs vs colmena)"
echo "========================================================================="
"$EPOCH_BIN" benchmark-all \
  --nix-nodes "${NIX_EVAL_NODES:-4,8,16,24}" \
  --worker-nodes "${WORKER_EVAL_NODES:-10,100,500,1000}" \
  --p2p-nodes "${P2P_FLEET_SIZES:-10,50,100,500,1000}" \
  --bench-nix-file "$SCRIPT_DIR/bench-eval.nix" \
  --colmena-key-template /tmp/investigation/colmena/src/nix/host/key_uploader.template.sh \
  --output-json "$OUT_JSON"

echo "========================================================================="
echo " Saved complete empirical JSON results to: $OUT_JSON"
echo "========================================================================="
