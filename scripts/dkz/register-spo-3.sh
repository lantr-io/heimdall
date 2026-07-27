#!/usr/bin/env bash
# run-dkz screencast — register demo SPO 3 into the on-chain spos_registry.
#
#   pool  : cold seed 0x23×32   -> pool13vzpeazl… (8b041cf4…)
#   bifrost: 0x11×31+0x03       -> cfc66869…
#   url   : http://127.0.0.1:18502
#
# Extra args pass through to `register-spo`; add --submit to broadcast:
#     ./register-spo-3.sh --submit
# NOTE: this SPO is ALREADY on the preprod registry (2026-06-30, tx c9365c18…). Against that live
# registry the build refuses with `registry: pool_id already registered` — that error IS the proof
# it is on-chain. To actually build/broadcast a registration, run against a fresh (re-bootstrapped)
# registry. Kept here as the exact, reproducible command + params.
set -eu

HD="$(cd "$(dirname "$0")/../.." && pwd)"   # heimdall repo root
cd "$HD"

BP="$HD/.b814cca.plutus.json"
if [ ! -f "$BP" ]; then
  git -C /home/rssh/packages/FluidTokens/ft-bifrost-bridge show b814cca:onchain/plutus.json > "$BP" \
    || { echo "need the b814cca blueprint at $BP"; exit 1; }
fi

exec ./target/debug/heimdall register-spo \
  --config heimdall-preprod.toml \
  --blueprint "$BP" \
  --registry-bootstrap 05520edf2d79e10954d7a7dbf99b271e2b25cd31a6fd15353787915b850d917c:0 \
  --treasury-nft-name 1e65fe8aa85835590a96ceb6d058a9ce6b7d55329e108da58c3ae0a43898fcff \
  --registry-ref 352c5fce28fc1c5c3dded7c02e9b96f5f07256305a532b5120d24d05f15f6f5c:0 \
  --cold-skey   2323232323232323232323232323232323232323232323232323232323232323 \
  --bifrost-skey 1111111111111111111111111111111111111111111111111111111111111103 \
  --bifrost-url http://127.0.0.1:18502 \
  "$@"
