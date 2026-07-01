#!/usr/bin/env bash
# run-dkz screencast — register demo SPO 1 into the on-chain spos_registry.
#
#   pool  : cold seed 0x21×32   -> pool10vn6nrh… (7b27a98e…)
#   bifrost: 0x11×31+0x01       -> 65666e23…
#   url   : http://127.0.0.1:18500
#
# Extra args pass through to `register-spo`; add --submit to broadcast:
#     ./register-spo-1.sh --submit
# NOTE: this SPO is ALREADY on the preprod registry (2026-06-30, tx 82ea5122…). Against that live
# registry the build refuses with `registry: pool_id already registered` — that error IS the proof
# it is on-chain. To actually build/broadcast a registration, run against a fresh (re-bootstrapped)
# registry. Kept here as the exact, reproducible command + params.
set -euo pipefail

HD="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # heimdall repo root
cd "$HD"

# The 2026-06-11 registry was deployed with the ft-bifrost-bridge `b814cca` blueprint; pin it
# (the current bip322 plutus.json compiles to a policy that is NOT on-chain). Auto-extract if missing.
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
  --cold-skey   2121212121212121212121212121212121212121212121212121212121212121 \
  --bifrost-skey 1111111111111111111111111111111111111111111111111111111111111101 \
  --bifrost-url http://127.0.0.1:18500 \
  "$@"
