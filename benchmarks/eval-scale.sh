#!/usr/bin/env bash
# Section 7.4.2: Plane 1 Head-to-Head Nix Evaluation & CoW Worker Pool Scaling Harness
# Compares `epoch` against `colmena` (`src/nix/hive/eval.nix`) and `deploy-rs` (`nix/transform-deploy.nix`)
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
echo " 1A. EPOCH vs COLMENA vs DEPLOY-RS: REAL NIX EVALUATION HEAD-TO-HEAD"
echo "========================================================================="
"$EPOCH_BIN" benchmark-eval \
  --compare-incumbents \
  --nix-nodes "${NIX_EVAL_NODES:-4,8,16}" \
  --bench-nix-file "$SCRIPT_DIR/bench-eval.nix"

echo "========================================================================="
echo " 1B. EPOCH PLANE 1 PRE-FORKED CoW WORKER POOL + BLAKE3 CACHE (N=10..1000)"
echo "========================================================================="
for n in 10 100 500 1000; do
  echo "--- Fleet Size N = $n (Archetypes = 8, Pre-forked CoW Workers = 4) ---"
  "$EPOCH_BIN" benchmark-eval --nodes "$n" --archetypes 8 --workers 4
done
