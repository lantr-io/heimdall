//! `CardanoPegInSource` backed by the Blockfrost REST API.
//!
//! Uses the `blockfrost` crate's `BlockfrostAPI` client and OpenAPI
//! types. Server-side asset filtering via `addresses_utxos_asset`
//! keeps bandwidth low. The source does NOT decode the inline datum —
//! it hands the raw CBOR bytes to `parse_pegin_request`, which knows
//! the `PegInDatum` Constr shape.

use async_trait::async_trait;

use crate::cardano::bf_http;
use crate::cardano::pegin_source::{CardanoOutRef, CardanoPegInRequest, CardanoPegInSource};
use crate::epoch::state::{EpochError, EpochResult};

pub struct BlockfrostPegInSource {
    base_url: String,
    project_id: String,
    address: String,
}

impl BlockfrostPegInSource {
    /// `project_id` is the Blockfrost API key (e.g. `preprodXXXXXX`).
    /// The network is auto-detected from the key prefix unless `blockfrost_url` overrides it.
    /// `address` is the bech32 script address carrying peg-in UTxOs.
    pub fn new(project_id: &str, address: impl Into<String>, blockfrost_url: Option<&str>) -> Self {
        Self {
            base_url: bf_http::base_url(project_id, blockfrost_url),
            project_id: project_id.to_string(),
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

        // Fetch all UTxOs at the address (raw HTTP, lenient parse — tolerates backends like
        // yaci-devkit that omit `tx_index`) and filter by policy locally. (The asset-filtered
        // endpoint wants the FULL `<policy><name>` unit on some backends, so we don't rely on it.)
        let utxos = bf_http::fetch_address_utxos(&self.base_url, &self.project_id, &self.address)
            .await
            .map_err(EpochError::Chain)?;

        let mut out = Vec::new();
        for utxo in utxos {
            // Keep only UTxOs carrying a token under the peg-in policy.
            if !utxo.amount.iter().any(|a| a.unit.starts_with(&policy_hex)) {
                continue;
            }
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
                // Filled in below, once per DISTINCT creating transaction.
                created_slot: None,
            });
        }

        // Batch membership needs the CREATION SLOT of each request (WI-049), and
        // it is not in the UTxO listing. One `/txs/{hash}` per distinct creating
        // transaction, hours apart — the cost the peg-out side already pays.
        //
        // The tip is this source's own read rather than the caller's: it is only
        // consulted when the backend omits `slot` (yaci-devkit), and `slot_at_time`
        // is exact for post-Shelley one-second slots, so two SPOs holding different
        // reference pairs still derive the same slot for the same block. A tip we
        // cannot read leaves the slots unresolved, which defers rather than admits.
        //
        // NOTE THE UNIT: `fetch_latest_block_slot_time` reports POSIX **seconds**
        // and `slot_at_time` takes **milliseconds**. Passing it through unscaled
        // is silent — every request lands thousands of slots in the future and is
        // deferred for ever.
        let tip = bf_http::fetch_latest_block_slot_time(&self.base_url, &self.project_id)
            .await
            .ok()
            .map(|(slot, time_secs)| (slot, time_secs.saturating_mul(1000)));
        // Collected rather than passed as a borrowing iterator: a `.iter().map(..)`
        // held across the await makes the closure's lifetime not general enough for
        // the async trait method.
        let hashes: Vec<String> = out
            .iter()
            .map(|r| hex::encode(r.cardano_utxo.tx_hash))
            .collect();
        let resolved =
            bf_http::resolve_tx_slots(&self.base_url, &self.project_id, hashes, tip, "pegin").await;
        for req in &mut out {
            req.created_slot = resolved
                .get(&hex::encode(req.cardano_utxo.tx_hash))
                .copied()
                .flatten();
        }

        out.sort_by(|a, b| a.cardano_utxo.cmp(&b.cardano_utxo));
        Ok(out)
    }
}
