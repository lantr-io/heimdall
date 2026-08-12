#!/bin/sh

# The peg-in Taproot internal key is the FROST group key Y_51 — the daemon
# reconstructs every deposit address under it, so a deposit built under anything
# else is unsweepable. Read it off `heimdall show-treasury` ("our Y_51: …") for
# the bridge you are depositing into; there is no local derivation for it.
: "${Y51:?set Y51 to the FROST group key (heimdall show-treasury)}"

cargo run --bin depositor -- \
  --config heimdall.testnet4.toml \
  --frost-key "$Y51" \
  --depositor-wif-file .keys/alice.wif \
  --deposit-amount-sat 4000 \
  --fee-sat 200
  # add --submit to broadcast (default is a dry run)
