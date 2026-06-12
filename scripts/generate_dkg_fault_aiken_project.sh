#!/usr/bin/env bash
set -euo pipefail

round="${1:-all}"
case "${round}" in
  round1 | round2 | all) ;;
  *)
    echo "usage: $0 [round1|round2|all]" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

RUSTC_BOOTSTRAP="${RUSTC_BOOTSTRAP:-1}" \
RUSTFLAGS="${RUSTFLAGS:--D warnings}" \
DKG_FAULT_ONCHAIN_GENERATE_ONLY=1 \
DKG_FAULT_ONCHAIN_ROUND="${round}" \
cargo bench --bench dkg_fault_onchain

echo
if [ "${round}" = "all" ]; then
  echo "Generated Aiken projects under target/dkg_fault_onchain/round1 and target/dkg_fault_onchain/round2."
else
  echo "Generated Aiken project under target/dkg_fault_onchain/${round}."
fi
echo "Run 'aiken build' inside a generated round directory to produce plutus.json."
