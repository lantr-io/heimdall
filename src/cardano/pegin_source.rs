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
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CardanoOutRef {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
}

impl std::fmt::Display for CardanoOutRef {
    /// `<tx_hash hex>#<index>` — the form cardano-cli takes and every explorer
    /// shows, so an outref in a log line can be pasted straight into a query.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured rather than field-accessed on purpose. `PartialEq`, `Ord`
        // and `Hash` are still derived, so a field added later would be COMPARED
        // but not PRINTED — and the first sign of that is an `assert_eq!` failure
        // whose left and right render identically, which is exactly the
        // undebuggable output this impl exists to remove. This way a new field is
        // a compile error here instead.
        let Self {
            tx_hash,
            output_index,
        } = self;
        write!(f, "{}#{}", hex::encode(tx_hash), output_index)
    }
}

/// Written out rather than derived, and identical to [`std::fmt::Display`].
///
/// The derive prints `tx_hash` as a 32-element list of DECIMAL bytes, so an
/// operator got `CardanoOutRef { tx_hash: [157, 22, 73, ...], output_index: 0 }`
/// where they needed a transaction id — unreadable, un-greppable, and
/// un-pasteable. Making the DEBUG form hex too is what fixes it everywhere at
/// once: `{:?}` reaches this type through log lines, `anyhow` context, and
/// assertion failures alike, and a hex outref is the more useful text in all
/// three.
impl std::fmt::Debug for CardanoOutRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
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
    /// Slot of the Cardano transaction that CREATED this request — the chain
    /// fact the batch's stability cutoff and FIFO order are computed from
    /// (spec §TM batches; WI-049). `None` when the backend could not resolve
    /// it, which every consumer MUST read as "defer to a later batch": a
    /// request this node cannot place in time must not be signed into a batch
    /// its peers would place differently.
    ///
    /// Deliberately NOT taken from the datum. A peg-in datum carries no
    /// creation time, and if it did it would be requester-set — the same reason
    /// `PegOutRequestData::created_slot` is chain-sourced.
    pub created_slot: Option<u64>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Both forms are hex, and both are the SAME text.
    ///
    /// Pinned because the failure it replaces was silent: `#[derive(Debug)]`
    /// rendered `tx_hash` as 32 decimal bytes, and every `{:?}` in a log line
    /// printed `CardanoOutRef { tx_hash: [157, 22, 73, ...], output_index: 0 }`
    /// where an operator needed a transaction id. Restoring the derive would
    /// reintroduce that without breaking anything a compiler can see.
    #[test]
    fn an_outref_prints_as_a_pasteable_txid() {
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = 0x9d;
        tx_hash[1] = 0x16;
        tx_hash[31] = 0xf4;
        let outref = CardanoOutRef {
            tx_hash,
            // Non-zero, because `#0` is also what an implementation that
            // hardcoded the separator-and-index would print: the index has to
            // discriminate, or the second half of the format is not pinned.
            output_index: 7,
        };

        let shown = outref.to_string();
        assert_eq!(
            shown, "9d160000000000000000000000000000000000000000000000000000000000f4#7",
            "the cardano-cli / explorer form, so it can be pasted into a query"
        );
        assert_eq!(
            format!("{outref:?}"),
            shown,
            "`{{:?}}` reaches this type through logs, error context and assertion \
             failures — it must not fall back to a list of decimal bytes"
        );
        // The one form the exact match above does NOT cover: `{:#?}` is a
        // separate path through the formatter, and a DERIVED Debug answers it
        // with the multi-line byte array this type was changed to stop printing.
        assert_eq!(
            format!("{outref:#?}"),
            shown,
            "the alternate/pretty form must not expand back into fields"
        );
    }
}
