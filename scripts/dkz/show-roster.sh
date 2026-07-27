#!/usr/bin/env bash
# run-dkz screencast, STEP 1 — read the on-chain SPO list + the stake-weighted DKG roster.
#
# Prints the 4 registered SPOs (the spos_registry linked list) and the stake-weighted
# DKG roster = 2 of 3: the 3 real-stake pools (20 ADA each); the stake-less legacy SPO
# 5ae193ab… is excluded (cardano.demo_exclude_unstaked = true).
set -eu

HD="$(cd "$(dirname "$0")/../.." && pwd)"   # heimdall repo root
cd "$HD"

# heimdall-preprod.toml pins registry_blueprint at this saved b814cca copy; extract if missing.
BP="$HD/.b814cca.plutus.json"
if [ ! -f "$BP" ]; then
  git -C /home/rssh/packages/FluidTokens/ft-bifrost-bridge show b814cca:onchain/plutus.json > "$BP" \
    || { echo "need the b814cca blueprint at $BP"; exit 1; }
fi

exec ./target/debug/heimdall show-roster --config heimdall-preprod.toml "$@"
