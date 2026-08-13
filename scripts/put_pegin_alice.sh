#!/bin/sh

# The deposit address is Taproot(Y_51; federation leaf + refund leaf), so BOTH keys
# are inputs to it. Y_51 is the FROST group key (the daemon reconstructs every deposit
# under it) and Y_FED is the federation emergency-sweep leaf key; neither has a local
# derivation. Read them off `heimdall show-treasury` / the bridge's Config. The CSV
# delay of the federation leaf comes from bitcoin.federation_csv_blocks in the config.
: "${Y51:?set Y51 to the FROST group key (heimdall show-treasury)}"
: "${Y_FED:?set Y_FED to the federation key (Config y_federation)}"
: "${FED_CSV:?set FED_CSV to the federation leaf CSV delay (Config params.federation_csv_blocks)}"

cargo run --bin depositor -- \
  --config heimdall.testnet4.toml \
  --frost-key "$Y51" \
  --y-federation "$Y_FED" \
  --federation-csv-blocks "$FED_CSV" \
  --depositor-wif-file .keys/alice.wif \
  --deposit-amount-sat 4000 \
  --fee-sat 200
  # add --submit to broadcast (default is a dry run)
