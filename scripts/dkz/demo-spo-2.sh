#!/usr/bin/env bash
# run-dkz screencast, STEP 2 — DKG instance for SPO 2 (bifrost 0x11×31+0x02, listens :18501).
#
# Run demo-spo-1/2/3.sh in three terminals, within ~60s of each other. Each identifies itself
# by its bifrost key off the on-chain registry, runs the DKG over HTTP, and derives the common
# group key. --deterministic makes it reproducible: all three converge on
#     Y_51 = b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854
# Do NOT stop at the group key — the run continues Sign → Submit and the LEADER (lowest id) posts the
# FROST-signed treasury movement to Cardano, printing:
#     [submit] Cardano oracle-update submitted: tx_hash=…
# That tx_hash is the end of the DKG round (submit_oracle=true → a REAL preprod post). Ctrl-C all three after it.
set -eu

HD="$(cd "$(dirname "$0")/../.." && pwd)"   # heimdall repo root
cd "$HD"

BP="$HD/.b814cca.plutus.json"
if [ ! -f "$BP" ]; then
  git -C /home/rssh/packages/FluidTokens/ft-bifrost-bridge show b814cca:onchain/plutus.json > "$BP" \
    || { echo "need the b814cca blueprint at $BP"; exit 1; }
fi

exec ./target/debug/heimdall demo --config heimdall-spo2.toml --deterministic "$@"
