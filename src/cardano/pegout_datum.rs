//! Read PegOut requests from `peg_out.ak` UTxOs on Cardano — the SPO's spec job
//! (technical_documentation §`peg_out.ak`: "SPOs read these UTxOs to include peg-out payments
//! in the Treasury Movement transaction").
//!
//! Each PegOut UTxO carries an inline `PegOutDatum` — since rev 5.1 an Aiken `Constr 0` with FOUR
//! fields: `[owner_auth, source_chain_destination_address, per_pegout_fee, created]`. Field[1] is
//! the raw Bitcoin scriptPubKey the TM must pay; the locked fBTC quantity in the UTxO value is the
//! GROSS peg-out amount. The destination + gross amount come from on-chain state, never from the
//! operator.
//!
//! **An open request is not an unpaid request.** A PegOut UTxO is spent only by its owner's
//! *Complete* transaction, which needs a membership proof against the completed-peg-outs trie —
//! hours later, or never. So this scan keeps returning requests earlier TMs already paid, and a
//! builder that pays everything it scans re-pays every withdrawal in every subsequent movement.
//! Two guards, at different layers:
//!
//!  - the completed-peg-outs trie (`cardano::cpo_trie`) is the DURABLE record — `build_tm` skips
//!    any `por_id` already in it;
//!    (a TM signed and broadcast but not yet Confirmed on Cardano), by counting the payments in
//!    the Confirmed TM datums' `fulfilled_peg_outs` lists plus still-live in-flight TMs.
//!
//! Field[2] `per_pegout_fee` is the request's OWN protocol fee, pinned from the Config floor at
//! lock time. `peg-out.ak`'s Complete branch binds the trie value against THIS field, never against
//! a current on-chain value, so the TM must pay `gross − datum.per_pegout_fee` exactly. That is
//! also what makes the fee a consensus input for FROST determinism: it comes from the datum every
//! SPO reads, not from local config.
//!
//! Field[3] `created` (POSIX ms) gates `peg_out.ak::Cancel`, which refunds the owner's fBTC once
//! `created + peg_out_cancel_timeout_ms` passes. `build_tm`'s freshness filter uses it to refuse
//! requests too close to that deadline — paying one is a treasury double spend if the owner then
//! cancels.
//!
//! The treasury-outpoint PIN is GONE. It was the pre-rev-5.1 mechanism binding a request to one
//! specific TM; the trie replaces it, so a request is completable by whichever TM pays it.

use pallas_primitives::PlutusData;

use crate::cardano::bf_http;
use crate::cardano::plutus;
use tracing::warn;

/// A peg-out the SPO must fulfil in the TM: pay `destination_script_pubkey` the GROSS
/// `amount_sat` minus this request's OWN `per_pegout_fee` (the deduction happens in
/// `bitcoin::tm_builder::build_tm`, not here).
#[derive(Debug, Clone)]
pub struct PegOutRequestData {
    pub destination_script_pubkey: Vec<u8>,
    /// Gross peg-out amount (the locked fBTC quantity); the BTC output pays this minus
    /// [`Self::per_pegout_fee`].
    pub amount_sat: u64,
    /// `per_pegout_fee` (datum field[2]): this request's protocol fee in satoshi, pinned at lock
    /// time. `peg-out.ak` binds the completed-peg-outs trie value against this exact value.
    pub per_pegout_fee: u64,
    /// `created` (datum field[3]): POSIX ms, the input to the freshness filter and to
    /// `peg_out.ak::Cancel`'s timeout.
    pub created: i64,
    /// The Cardano UTxO `(tx_hash, output_index)` holding this request. Diagnostics + a total
    /// sort order; never enters the TM bytes.
    pub cardano_utxo: (String, u32),
    /// `sha256(serialise_data(OutputReference))` of this UTxO — the completed-peg-outs trie key
    /// `peg-out.ak` recomputes on-chain from `peg_out_input.output_reference`.
    pub por_id: [u8; 32],
    /// This UTxO's outpoint in the 36-byte hint encoding (tx hash ‖ index LE), published in the
    /// TM datum's `fulfilled_por_outpoints`.
    pub outpoint: [u8; 36],
    /// Absolute Cardano slot at which this request UTxO was CREATED, filled in by
    /// [`resolve_created_slots`] (`None` until then).
    ///
    /// This — not the datum's `created` — is what the TM batch cutoff `C_i` compares
    /// against. `created` is requester-set and verified by nothing, so a request could
    /// backdate itself into a batch its peers would exclude; the creating transaction's
    /// slot is a chain fact every SPO reads identically. `None` means the slot could not
    /// be resolved, and the batch freeze treats that as "not provably old enough" and
    /// defers the request rather than guessing.
    pub created_slot: Option<u64>,
}

impl PegOutRequestData {
    /// What the TM actually pays: `gross − per_pegout_fee`, saturating at 0.
    #[must_use]
    pub fn net_sat(&self) -> u64 {
        self.amount_sat.saturating_sub(self.per_pegout_fee)
    }
}

/// The TM-relevant fields of a `PegOutDatum`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PegOutDatumFields {
    /// field[1] `source_chain_destination_address` — the raw Bitcoin scriptPubKey to pay.
    pub destination_script_pubkey: Vec<u8>,
    /// field[2] `per_pegout_fee`.
    pub per_pegout_fee: u64,
    /// field[3] `created`, POSIX ms.
    pub created: i64,
}

/// Parse the TM-relevant `PegOutDatum` fields. The datum is the Aiken `PegOutDatum` record —
/// constructor 0, exactly 4 fields since rev 5.1; field[0] (`owner_auth`) is an
/// `AuthorizationMethod` sum type and not the SPO's business.
///
/// A NEGATIVE `per_pegout_fee` is rejected: on-chain the Complete branch computes
/// `bridged_tokens_locked - per_pegout_fee`, so a negative fee would demand the TM pay MORE than
/// the request locked — treasury funds for nothing. Rejecting here means the caller skips the
/// UTxO, and the owner can still Cancel for a refund.
///
/// Constructor 0 is accepted in BOTH plutus-core encodings — the compact tag 121 form and the
/// general tag-102 + `any_constructor` form — because the user controls the datum bytes at lock
/// time and a Haskell node accepts either; rejecting the 102 form would drop a legitimate,
/// completable peg-out (the sibling registry/treasury decoders already accept both).
pub fn parse_pegout_datum(data: &PlutusData) -> Result<PegOutDatumFields, String> {
    let fields = plutus::constr_fields(data, 0).map_err(|e| format!("PegOutDatum: {e}"))?;
    if fields.len() != 4 {
        return Err(format!(
            "PegOutDatum: expected 4 fields, got {}",
            fields.len()
        ));
    }
    let destination_script_pubkey = plutus::field_bytes(fields, 1).map_err(|_| {
        "PegOutDatum: field[1] (source_chain_destination_address) is not BoundedBytes".to_string()
    })?;
    let fee = plutus::field_int(fields, 2)
        .map_err(|_| "PegOutDatum: field[2] (per_pegout_fee) is not an Int".to_string())?;
    let per_pegout_fee = u64::try_from(fee)
        .map_err(|_| format!("PegOutDatum: field[2] (per_pegout_fee) is negative: {fee}"))?;
    let created = plutus::field_int(fields, 3)
        .map_err(|_| "PegOutDatum: field[3] (created) is not an Int".to_string())?;
    Ok(PegOutDatumFields {
        destination_script_pubkey,
        per_pegout_fee,
        created,
    })
}

/// The result of one peg-out address scan: the decodable requests, plus how many UTxOs
/// were dropped because their datum could not be decoded.
///
/// `malformed` is reported, not just logged (WI-031 item 8): the peg-out address is
/// permissionlessly payable, so a request whose datum heimdall refuses is invisible in the
/// "scanned N open peg-out request(s)" count — no TM ever pays it, and while its owner can
/// still Cancel, an operator watching only the count has no signal that anything was lost.
#[derive(Debug, Clone, Default)]
pub struct PegOutScan {
    pub requests: Vec<PegOutRequestData>,
    /// UTxOs holding the bridged token whose datum did not decode as a `PegOutDatum`.
    pub malformed: usize,
}

/// Fetch every PegOut request at `pegout_address`, identified by carrying the `fbtc_unit` token
/// (`<policy_hex><asset_name_hex>`). Returns the destination scriptPubKey, the datum-pinned fee and
/// `created`, the request identity (`por_id`, `outpoint`), and the locked fBTC amount (from the
/// value) for each, in deterministic order — so two SPOs reading the same chain state build the
/// same TM.
///
/// These are ALL open requests, including ones an earlier TM already paid (they linger until their
/// owner completes them). What filters those out is the completed-peg-outs trie, keyed by
/// `por_id`: hand it to `build_tm`, which skips any request already recorded in it
/// (`SkipReason::AlreadyCompleted`).
pub async fn fetch_pegout_requests(
    base_url: &str,
    project_id: &str,
    pegout_address: &str,
    fbtc_unit: &str,
) -> Result<PegOutScan, String> {
    let utxos = bf_http::fetch_address_utxos(base_url, project_id, pegout_address).await?;

    // Blockfrost emits units as lowercase hex; normalise the operator-supplied unit so a
    // copy-pasted uppercase value doesn't silently match zero UTxOs (→ a TM that pays no peg-outs).
    let fbtc_unit = fbtc_unit.trim().to_ascii_lowercase();

    let mut out = Vec::new();
    let mut malformed = 0usize;
    for utxo in utxos {
        // The peg-out amount is the locked fBTC quantity in the value (no datum field for it).
        let Some(amount_entry) = utxo.amount.iter().find(|a| a.unit == fbtc_unit) else {
            continue; // no fBTC under this UTxO — not a peg-out request
        };

        // The peg-out address is permissionlessly payable: anyone can park a UTxO with a malformed
        // datum, possibly unspendable. SKIP such a UTxO (like the no-datum case) rather than abort
        // the whole fetch — one poison UTxO must not block every Treasury Movement bridge-wide.
        let request = (|| -> Result<PegOutRequestData, String> {
            let amount_sat: u64 = amount_entry
                .quantity
                .parse()
                .map_err(|e| format!("bad fBTC quantity '{}': {e}", amount_entry.quantity))?;
            let datum_hex = utxo
                .inline_datum
                .as_deref()
                .ok_or_else(|| "no inline datum".to_string())?;
            let datum_cbor = hex::decode(datum_hex).map_err(|e| format!("datum hex: {e}"))?;
            let plutus: PlutusData = pallas_codec::minicbor::decode(&datum_cbor)
                .map_err(|e| format!("datum cbor: {e}"))?;
            let parsed = parse_pegout_datum(&plutus)?;
            let tx_hash: [u8; 32] = hex::decode(&utxo.tx_hash)
                .map_err(|e| format!("tx hash hex: {e}"))?
                .try_into()
                .map_err(|v: Vec<u8>| format!("tx hash is {} bytes, expected 32", v.len()))?;
            Ok(PegOutRequestData {
                destination_script_pubkey: parsed.destination_script_pubkey,
                amount_sat,
                per_pegout_fee: parsed.per_pegout_fee,
                created: parsed.created,
                cardano_utxo: (utxo.tx_hash.clone(), utxo.output_index),
                por_id: crate::cardano::cpo_trie::por_id(&tx_hash, u64::from(utxo.output_index)),
                outpoint: crate::cardano::cpo_trie::hint_bytes(&tx_hash, utxo.output_index),
                created_slot: None,
            })
        })();
        match request {
            Ok(req) => out.push(req),
            Err(why) => {
                malformed += 1;
                warn!(
                    "[pegout] skipping malformed peg-out UTxO {}#{}: {why}",
                    utxo.tx_hash, utxo.output_index
                );
            }
        }
    }

    // Total order (the UTxO ref breaks ties between otherwise identical requests) so the scan is
    // reproducible across SPOs even with duplicate (destination, amount) requests.
    out.sort_by(|a, b| {
        a.destination_script_pubkey
            .cmp(&b.destination_script_pubkey)
            .then(a.amount_sat.cmp(&b.amount_sat))
            .then(a.cardano_utxo.cmp(&b.cardano_utxo))
    });
    Ok(PegOutScan {
        requests: out,
        malformed,
    })
}

/// Fill in each request's [`PegOutRequestData::created_slot`] from the chain.
///
/// One `/txs/{hash}` lookup per DISTINCT creating transaction — several requests
/// minted together cost one request, and the count is bounded by the number of open
/// peg-outs, which the per-batch capacity already caps. Batches are hours apart, so
/// this is a handful of reads per movement.
///
/// `tip` is a known `(slot, time_ms)` pair on the same chain, used only when the
/// backend omits `slot` from `/txs` (yaci-devkit). A request whose slot cannot be
/// resolved keeps `None`: the freeze then defers it instead of assuming it is old
/// enough, so a flaky lookup costs latency, never a divergent batch.
pub async fn resolve_created_slots(
    base_url: &str,
    project_id: &str,
    requests: &mut [PegOutRequestData],
    tip: Option<(u64, i64)>,
) {
    // Collected, not a borrowing iterator: held across the await it makes the
    // closure's lifetime not general enough for `query_pegout_requests`.
    let hashes: Vec<String> = requests.iter().map(|r| r.cardano_utxo.0.clone()).collect();
    let resolved = bf_http::resolve_tx_slots(base_url, project_id, hashes, tip, "pegout").await;
    for req in requests.iter_mut() {
        req.created_slot = resolved.get(&req.cardano_utxo.0).copied().flatten();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_primitives::conway::Constr;
    use pallas_primitives::{BoundedBytes, MaybeIndefArray};

    fn bytes(b: &[u8]) -> PlutusData {
        PlutusData::BoundedBytes(BoundedBytes::from(b.to_vec()))
    }

    fn pegout_datum(
        ctor_tag: u64,
        any_constructor: Option<u64>,
        fields: Vec<PlutusData>,
    ) -> PlutusData {
        PlutusData::Constr(Constr {
            tag: ctor_tag,
            any_constructor,
            fields: MaybeIndefArray::Indef(fields),
        })
    }

    fn int(n: i64) -> PlutusData {
        crate::cardano::plutus::int(n)
    }

    /// The rev-5.1 4-field datum: `[owner_auth, dest_spk, per_pegout_fee, created]`.
    fn four_fields(spk: &[u8]) -> Vec<PlutusData> {
        vec![
            // owner_auth is an AuthorizationMethod Constr, not bytes — the parser must not care.
            pegout_datum(121, None, vec![bytes(&[0x7a; 28])]),
            bytes(spk),
            int(1_000),
            int(1_700_000_000_000),
        ]
    }

    fn request(spk: &[u8], amount_sat: u64, fee: u64) -> PegOutRequestData {
        let tx = [0xab; 32];
        PegOutRequestData {
            destination_script_pubkey: spk.to_vec(),
            amount_sat,
            per_pegout_fee: fee,
            created: 1_700_000_000_000,
            cardano_utxo: ("ab".repeat(32), 0),
            por_id: crate::cardano::cpo_trie::por_id(&tx, 0),
            outpoint: crate::cardano::cpo_trie::hint_bytes(&tx, 0),
            created_slot: Some(0),
        }
    }

    /// The batch cutoff and the FIFO order key off `created_slot` — the CREATING
    /// transaction's slot — never the datum's `created`, which the requester sets and
    /// nothing verifies. A backdated request must not be able to talk its way into a
    /// batch its peers would exclude.
    #[test]
    fn created_slot_is_chain_sourced_and_independent_of_the_datum() {
        let mut r = request(b"\x51\x20dest", 100_000, 1_000);
        assert_eq!(r.created, 1_700_000_000_000, "the datum's own field");
        assert_eq!(
            r.created_slot,
            Some(0),
            "resolved separately, from the chain"
        );
        // Backdating the datum leaves the chain-sourced slot untouched.
        r.created = 1;
        assert_eq!(r.created_slot, Some(0));
    }

    #[test]
    fn extracts_dest_fee_and_created_from_tag_121() {
        let d = pegout_datum(121, None, four_fields(b"\x51\x20destination"));
        let p = parse_pegout_datum(&d).unwrap();
        assert_eq!(p.destination_script_pubkey, b"\x51\x20destination");
        assert_eq!(p.per_pegout_fee, 1_000);
        assert_eq!(p.created, 1_700_000_000_000);
    }

    // Constructor 0 in the general tag-102 form must be accepted — it's legal Plutus data the node
    // accepts, so rejecting it would drop a completable peg-out.
    #[test]
    fn extracts_fields_from_tag_102_constructor_0() {
        let d = pegout_datum(102, Some(0), four_fields(b"\x51\x20destination"));
        let p = parse_pegout_datum(&d).unwrap();
        assert_eq!(p.destination_script_pubkey, b"\x51\x20destination");
        assert_eq!(p.per_pegout_fee, 1_000);
    }

    #[test]
    fn rejects_wrong_constructor_and_shape() {
        // constructor 1 (tag 122) is not a PegOutDatum
        assert!(parse_pegout_datum(&pegout_datum(122, None, four_fields(b"x"))).is_err());
        // 102 form with a non-zero constructor
        assert!(parse_pegout_datum(&pegout_datum(102, Some(1), four_fields(b"x"))).is_err());
        // wrong field count
        assert!(parse_pegout_datum(&pegout_datum(121, None, vec![bytes(b"a")])).is_err());
        // not a Constr at all
        assert!(parse_pegout_datum(&bytes(b"nope")).is_err());
    }

    // The OLD 3-field datum (with the retired treasury-outpoint pin) must no longer parse: its
    // field[2] is a 36-byte pin, not a fee, and reading it as one would produce nonsense amounts.
    #[test]
    fn rejects_the_retired_three_field_datum() {
        let old = pegout_datum(
            121,
            None,
            vec![bytes(b"owner"), bytes(b"\x51\x20dest"), bytes(&[0xaa; 36])],
        );
        assert!(parse_pegout_datum(&old).is_err());
    }

    #[test]
    fn rejects_non_int_fee_or_created() {
        let bad_fee = pegout_datum(
            121,
            None,
            vec![bytes(b"o"), bytes(b"\x51\x20d"), bytes(b"nope"), int(1)],
        );
        assert!(parse_pegout_datum(&bad_fee).is_err());
        let bad_created = pegout_datum(
            121,
            None,
            vec![bytes(b"o"), bytes(b"\x51\x20d"), int(1), bytes(b"nope")],
        );
        assert!(parse_pegout_datum(&bad_created).is_err());
    }

    // On-chain the Complete branch computes `locked - per_pegout_fee`; a negative fee would demand
    // the TM pay MORE than the request locked. The owner can still Cancel, so skipping is safe.
    #[test]
    fn rejects_a_negative_fee() {
        let d = pegout_datum(
            121,
            None,
            vec![bytes(b"o"), bytes(b"\x51\x20d"), int(-1), int(0)],
        );
        assert!(parse_pegout_datum(&d).is_err());
    }

    // field[1] must be raw bytes — a Constr there is not a scriptPubKey.
    #[test]
    fn rejects_non_bytes_destination() {
        let bad = pegout_datum(
            121,
            None,
            vec![bytes(b"a"), pegout_datum(121, None, vec![]), int(0), int(0)],
        );
        assert!(parse_pegout_datum(&bad).is_err());
    }
}
