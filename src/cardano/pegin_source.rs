//! The `CardanoPegInSource` trait — the seam crossing from the epoch
//! state machine into "wherever peg-in requests come from". Real
//! impl is `pallas_source::PallasPegInSource` (N2C against a running
//! Cardano node); test impl is `mock::MockCardanoPegInSource`.
//!
//! Returned peg-ins are guaranteed ≥100 Bitcoin blocks deep by
//! construction: they are oracle-owned UTxOs on Cardano, and the
//! watchtower/Binocular oracle won't publish a peg-in request until
//! the depositor's BTC deposit has ≥100 confirmations. The SPO does
//! NOT re-verify BTC confirmations.
//!
//! TODO: the trait is one-shot polling today. A real deployment wants
//! ChainSync-backed subscription for lower-latency collection; extend
//! with `fn subscribe_pegin_requests(...) -> Stream<...>` once the
//! one-shot path is stable.

use async_trait::async_trait;

use crate::epoch::state::EpochResult;

/// A Cardano UTxO reference: `(tx_hash, output_index)`. 32-byte hash
/// to match pallas' `Hash<32>` / `TransactionInput.transaction_id`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CardanoOutRef {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
}

/// A peg-in request as seen on Cardano: the UTxO that carries it and
/// the raw CBOR bytes of its inline datum (`PegInDatum` Constr).
#[derive(Debug, Clone)]
pub struct CardanoPegInRequest {
    /// The Cardano UTxO carrying this request. Used for dedupe across
    /// poll rounds and, eventually, for spending the request UTxO
    /// when the peg-in completes.
    pub cardano_utxo: CardanoOutRef,
    /// Raw CBOR-encoded inline datum. `parse_pegin_request` in
    /// `pegin_datum.rs` decodes this as a Plutus `Constr 0 [...]`
    /// matching the Aiken `PegInDatum` type and extracts the raw BTC
    /// tx from field index 1 (`source_chain_peg_in_raw_tx`).
    pub datum_cbor: Vec<u8>,
}

#[async_trait]
pub trait CardanoPegInSource: Send + Sync {
    /// Fetch every peg-in request currently locked under `policy_id` at
    /// the source's configured script address. Deterministic ordering
    /// (sorted by `cardano_utxo`) is required so that two SPOs polling
    /// the same chain state produce the same frozen set.
    async fn query_pegin_requests(
        &self,
        policy_id: &[u8; 28],
    ) -> EpochResult<Vec<CardanoPegInRequest>>;
}
