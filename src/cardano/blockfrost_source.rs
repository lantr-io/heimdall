//! `CardanoPegInSource` backed by the Blockfrost REST API.
//!
//! Uses the `blockfrost` crate's `BlockfrostAPI` client and OpenAPI
//! types. Server-side asset filtering via `addresses_utxos_asset`
//! keeps bandwidth low. The source does NOT decode the inline datum —
//! it hands the raw CBOR bytes to `parse_pegin_request`, which knows
//! the `PegInDatum` Constr shape.

use async_trait::async_trait;
use blockfrost::{BlockFrostSettings, BlockfrostAPI, Pagination};

use crate::cardano::pegin_source::{CardanoOutRef, CardanoPegInRequest, CardanoPegInSource};
use crate::epoch::state::{EpochError, EpochResult};

pub struct BlockfrostPegInSource {
    api: BlockfrostAPI,
    address: String,
}

impl BlockfrostPegInSource {
    /// `project_id` is the Blockfrost API key (e.g. `preprodXXXXXX`).
    /// The network is auto-detected from the key prefix. `address` is
    /// the bech32 script address carrying peg-in UTxOs.
    pub fn new(project_id: &str, address: impl Into<String>) -> Self {
        let api = BlockfrostAPI::new(project_id, BlockFrostSettings::new());
        Self {
            api,
            address: address.into(),
        }
    }
}

#[async_trait]
impl CardanoPegInSource for BlockfrostPegInSource {
    async fn query_pegin_requests(
        &self,
        policy_id: &[u8; 28],
    ) -> EpochResult<Vec<CardanoPegInRequest>> {
        let policy_hex = hex::encode(policy_id);

        // Blockfrost's asset-filtered endpoint wants `<policy_hex><asset_name_hex>`.
        // We pass just the policy hex — Blockfrost matches all assets
        // under that policy at the address. Blockfrost returns 404
        // when there are no matching UTxOs, which is not an error.
        let utxos = match self
            .api
            .addresses_utxos_asset(&self.address, &policy_hex, Pagination::all())
            .await
        {
            Ok(u) => u,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("404") || msg.contains("Not Found") {
                    return Ok(vec![]);
                }
                return Err(EpochError::Chain(format!("blockfrost: {e}")));
            }
        };

        let mut out = Vec::new();
        for utxo in utxos {
            // Inline datum: Blockfrost returns the CBOR as a hex string.
            // We pass the raw bytes through — the parser decodes the
            // Constr shape.
            let Some(datum_hex) = &utxo.inline_datum else {
                continue;
            };
            let datum_cbor = match hex::decode(datum_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let tx_hash_bytes = match hex::decode(&utxo.tx_hash) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => continue,
            };

            out.push(CardanoPegInRequest {
                cardano_utxo: CardanoOutRef {
                    tx_hash: tx_hash_bytes,
                    output_index: utxo.output_index as u32,
                },
                datum_cbor,
            });
        }

        out.sort_by(|a, b| a.cardano_utxo.cmp(&b.cardano_utxo));
        Ok(out)
    }
}
