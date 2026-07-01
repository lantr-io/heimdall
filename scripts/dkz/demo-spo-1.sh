#!/usr/bin/env bash
# run-dkz screencast, STEP 2 — DKG instance for SPO 1 (bifrost 0x11×31+0x01, listens :18500).
#
# Run demo-spo-1/2/3.sh in three terminals, within ~60s of each other. Each identifies itself
# by its bifrost key off the on-chain registry, runs the DKG over HTTP, and derives the common
# group key. --deterministic makes it reproducible: all three converge on
#     Y_51 = b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854
# Ctrl-C after the "PublishKeys: group_key = …" line (this is DKG-only; ignore CollectPegins/BuildTm).
set -euo pipefail

HD="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # heimdall repo root
cd "$HD"

BP="$HD/.b814cca.plutus.json"
if [ ! -f "$BP" ]; then
  git -C /home/rssh/packages/FluidTokens/ft-bifrost-bridge show b814cca:onchain/plutus.json > "$BP" \
    || { echo "need the b814cca blueprint at $BP"; exit 1; }
fi

exec ./target/debug/heimdall demo --config heimdall-spo1.toml --deterministic "$@"
