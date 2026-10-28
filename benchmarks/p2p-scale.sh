#!/usr/bin/env bash
# Section 7.4.2: Plane 2 Store-Hash-Normalized FastCDC + Rack-Aware QUIC P2P Scaling Harness
# Compares `epoch` against `deploy-rs` and `colmena` whole-NAR star-push across N = 10..1000
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
echo " 2A. EPOCH vs DEPLOY-RS vs COLMENA: PLANE 2 FLEET SCALING (N=10..1000)"
echo "========================================================================="
"$EPOCH_BIN" benchmark-p2p --compare-incumbents --fleet-sizes "${P2P_FLEET_SIZES:-10,50,100,500,1000}" --racks 25 --fanout 4

echo "========================================================================="
echo " 2B. EPOCH PLANE 2 1,000-NODE SUMMARY (N = 1000, 25 Racks, k=4)"
echo "========================================================================="
"$EPOCH_BIN" benchmark-p2p --nodes 1000 --racks 25 --fanout 4
