//! Read PegOut requests from `peg_out.ak` UTxOs on Cardano — the SPO's spec job
//! (technical_documentation §`peg_out.ak`: "SPOs read these UTxOs to include peg-out payments
//! in the Treasury Movement transaction").
//!
//! Each PegOut UTxO carries an inline `PegOutDatum` (Aiken `Constr 0` with 3 fields:
//! `[owner_auth, source_chain_destination_address, source_chain_treasury_utxo_id]`). Field[1] is
//! the raw Bitcoin scriptPubKey the TM must pay; the locked fBTC quantity in the UTxO value is the
//! GROSS peg-out amount. The destination + gross amount come from on-chain state, never from the
//! operator.
//!
//! **An open request is not an unpaid request.** A PegOut UTxO is spent only by its owner's
//! *Complete* transaction, which needs the paying TM's Bitcoin confirmation plus an oracle
//! proof — hours later, or never. So this scan keeps returning requests earlier TMs already paid,
//! and a builder that pays everything it scans re-pays every withdrawal in every subsequent
//! movement. [`PaidPegOuts`] + [`select_unpaid`] are the guard: the paid multiset is reconstructed
//! from the Confirmed TM datums' `fulfilled_peg_outs` lists (plus still-live in-flight TMs) and
//! subtracted from the open set, so each request is paid exactly once.
//!
//! Field[2] `source_chain_treasury_utxo_id` pins the ONE Bitcoin treasury outpoint the paying TM
//! must spend (36 bytes: txid internal order ++ vout LE — the encoding binocular's `pegout-request`
//! writes and `TmDatum.swept` uses). Completion delegates to the on-chain
//! `legit_treasury_movement_and_peg_out_produced` verifier (Config field 7), which proves from the
//! raw TM bytes that the TM *spends that outpoint* AND pays the destination, so only the pinned TM
//! can complete a request — see [`partition_by_pin`].
//!
//! The BTC output does NOT pay the gross amount in full: per technical_documentation §"Treasury
//! Movement" ("Amounts and fees"), each peg-out output = gross amount − a fixed per-peg-out
//! PROTOCOL fee (covering the miner-fee share + protocol operating costs), and the treasury change
//! absorbs the Bitcoin miner fee. The fee must be a protocol-wide parameter so every SPO builds
//! byte-identical TM bytes (FROST determinism) — see the fee-source WI and technical_questions.md.
//! The deduction is applied downstream in `bitcoin::tm_builder::build_tm`; this module only reads
//! the gross amount + destination.

use std::collections::HashMap;

use pallas_primitives::PlutusData;

use crate::cardano::bf_http;
use crate::cardano::plutus;

/// A peg-out the SPO must fulfil in the TM: pay `destination_script_pubkey` the GROSS
/// `amount_sat` minus the per-peg-out protocol fee (the fee deduction happens in
/// `bitcoin::tm_builder::build_tm`, not here).
#[derive(Debug, Clone)]
pub struct PegOutRequestData {
    pub destination_script_pubkey: Vec<u8>,
    /// Gross peg-out amount (the locked fBTC quantity); the BTC output pays this minus the
    /// per-peg-out protocol fee.
    pub amount_sat: u64,
    /// `source_chain_treasury_utxo_id` (datum field[2]): the 36-byte Bitcoin outpoint (txid
    /// internal ++ vout LE) the paying TM MUST spend. Only a TM spending this outpoint may pay
    /// this request — see [`select_fulfillable`].
    pub pinned_treasury_outpoint: [u8; 36],
    /// The Cardano UTxO `(tx_hash, output_index)` holding this request. Diagnostics + a total
    /// sort order; never enters the TM bytes.
    pub cardano_utxo: (String, u32),
}

/// Parse the two TM-relevant `PegOutDatum` fields: `source_chain_destination_address` (field[1],
/// the raw Bitcoin scriptPubKey to pay) and `source_chain_treasury_utxo_id` (field[2], the 36-byte
/// treasury outpoint the paying TM must spend). The datum is the Aiken `PegOutDatum` record —
/// constructor 0, exactly 3 fields; field[0] (`owner_auth`) is not the SPO's business.
///
/// A field[2] that is not exactly 36 bytes cannot match any outpoint, so the on-chain produced
/// verifier could never accept a TM as fulfilling it — reject here (the caller skips the UTxO)
/// rather than pay BTC for a request that can never complete.
///
/// Constructor 0 is accepted in BOTH plutus-core encodings — the compact tag 121 form and the
/// general tag-102 + `any_constructor` form — because the user controls the datum bytes at lock
/// time and a Haskell node accepts either; rejecting the 102 form would drop a legitimate,
/// completable peg-out (the sibling registry/treasury decoders already accept both).
pub fn parse_pegout_datum(data: &PlutusData) -> Result<(Vec<u8>, [u8; 36]), String> {
    let fields = plutus::constr_fields(data, 0).map_err(|e| format!("PegOutDatum: {e}"))?;
    if fields.len() != 3 {
        return Err(format!(
            "PegOutDatum: expected 3 fields, got {}",
            fields.len()
        ));
    }
    let spk = plutus::field_bytes(fields, 1).map_err(|_| {
        "PegOutDatum: field[1] (source_chain_destination_address) is not BoundedBytes".to_string()
    })?;
    let pin_bytes = plutus::field_bytes(fields, 2).map_err(|_| {
        "PegOutDatum: field[2] (source_chain_treasury_utxo_id) is not BoundedBytes".to_string()
    })?;
    let pinned: [u8; 36] = pin_bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "PegOutDatum: field[2] (source_chain_treasury_utxo_id) must be a 36-byte outpoint, \
             got {} bytes",
            v.len()
        )
    })?;
    Ok((spk, pinned))
}

/// The peg-out payments already committed on Bitcoin by earlier Treasury Movements, as a
/// **multiset** keyed by `(destination scriptPubKey, satoshi amount actually paid)`.
///
/// This is the double-payment guard. A PegOut UTxO stays at the `peg_out.ak` address until its
/// owner completes it — which needs the TM's Bitcoin confirmation plus an oracle proof, so it lags
/// by hours or never happens — and every later scan therefore keeps returning requests an earlier
/// TM already paid. Heimdall's only record of what was paid is the Confirmed TM datum's
/// `fulfilled_peg_outs` list, so the payable set is "open requests minus what those datums show
/// already paid".
///
/// **A multiset, not a set.** The datum records only `(scriptPubKey, amount)` — there is no request
/// identity in it — and several distinct PegOut UTxOs legitimately share one `(destination,
/// amount)` pair (the live preprod bridge has three identical 2 500-sat requests to one address).
/// A set-based filter would drop all of them once one was paid, stranding the rest's fBTC forever.
/// Counting pays each request exactly once.
#[derive(Debug, Clone, Default)]
pub struct PaidPegOuts {
    counts: HashMap<(Vec<u8>, u64), usize>,
}

impl PaidPegOuts {
    /// Build the multiset from on-chain TM records.
    ///
    /// - `confirmed`: EVERY Confirmed record at the TM validator address, not just the ones on the
    ///   walked chain. A Confirmed record can only be minted through the confirm transition, which
    ///   proves the BTC tx was mined, so an off-chain-path record still evidences a real payment.
    ///   Over-counting only under-pays (recoverable by the request owner), while under-counting
    ///   double-pays treasury BTC irrecoverably.
    /// - `live_unconfirmed`: outputs of Unconfirmed (in-flight) TMs that can still confirm. Their
    ///   payments are already committed in FROST-signed Bitcoin bytes, so they must not be paid a
    ///   second time. Callers MUST exclude *dead* in-flight TMs (ones spending an outpoint a
    ///   Confirmed TM already swept — they can never confirm); counting those would strand their
    ///   peg-outs permanently.
    ///
    /// Output 0 of every TM is the treasury continuation, never a peg-out payment, and is skipped —
    /// otherwise a treasury value that happened to equal a pending request's amount would mask it.
    #[must_use]
    pub fn from_records<'a>(
        confirmed: &[crate::cardano::treasury_datum::ConfirmedTm],
        live_unconfirmed: impl Iterator<Item = &'a crate::cardano::treasury_datum::UnconfirmedTm>,
    ) -> Self {
        let mut counts: HashMap<(Vec<u8>, u64), usize> = HashMap::new();
        for tm in confirmed {
            for out in tm.outputs.iter().skip(1) {
                *counts
                    .entry((out.script_pub_key.clone(), out.amount))
                    .or_default() += 1;
            }
        }
        for tm in live_unconfirmed {
            for (value, spk) in tm.outputs.iter().skip(1) {
                *counts
                    .entry((spk.as_bytes().to_vec(), value.to_sat()))
                    .or_default() += 1;
            }
        }
        Self { counts }
    }

    /// Build the multiset from an already-flattened payment list — one entry per payment,
    /// duplicates included (the `CardanoChain::query_paid_pegout_payments` shape).
    pub fn from_payments<'a>(payments: impl Iterator<Item = (&'a [u8], u64)>) -> Self {
        let mut counts: HashMap<(Vec<u8>, u64), usize> = HashMap::new();
        for (spk, sat) in payments {
            *counts.entry((spk.to_vec(), sat)).or_default() += 1;
        }
        Self { counts }
    }

    /// Total number of recorded peg-out payments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.counts.values().sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.values().all(|c| *c == 0)
    }

    /// How many payments of `(spk, net_sat)` are still unaccounted for.
    #[must_use]
    pub fn remaining(&self, spk: &[u8], net_sat: u64) -> usize {
        self.counts
            .get(&(spk.to_vec(), net_sat))
            .copied()
            .unwrap_or(0)
    }

    /// Claim one recorded payment of `(spk, net_sat)`. `true` means this request was already paid
    /// (and the credit is consumed, so the NEXT identical request is not also filtered out).
    pub fn claim(&mut self, spk: &[u8], net_sat: u64) -> bool {
        match self.counts.get_mut(&(spk.to_vec(), net_sat)) {
            Some(n) if *n > 0 => {
                *n -= 1;
                true
            }
            _ => false,
        }
    }
}

/// Split open peg-out requests into the ones still owed a payment and the ones an earlier TM
/// already paid, consuming one credit from `paid` per matched request.
///
/// The match is on the amount the TM actually pays — `gross − per_pegout_fee` — because that is
/// what a Confirmed datum records. A request whose gross does not exceed the fee has no payable
/// amount at all; it is left in `unpaid` and dropped downstream by `build_tm` (which owns the dust
/// and non-standard-script skips), so the two skip rules stay in one place.
///
/// Deterministic for FROST: the outcome depends only on the Cardano snapshot, and requests sharing
/// one `(destination, net amount)` key produce byte-identical outputs, so *which* of them is
/// filtered cannot change the TM bytes.
#[must_use]
pub fn select_unpaid(
    requests: Vec<PegOutRequestData>,
    per_pegout_fee_sat: u64,
    paid: &mut PaidPegOuts,
) -> (Vec<PegOutRequestData>, Vec<PegOutRequestData>) {
    let mut unpaid = Vec::new();
    let mut already_paid = Vec::new();
    for r in requests {
        let net = r.amount_sat.saturating_sub(per_pegout_fee_sat);
        if net > 0 && paid.claim(&r.destination_script_pubkey, net) {
            already_paid.push(r);
        } else {
            unpaid.push(r);
        }
    }
    (unpaid, already_paid)
}

/// Partition by the datum's pinned treasury outpoint: requests naming `treasury_outpoint` as the
/// TM that must pay them, and requests naming some other (usually already-spent) outpoint.
///
/// Per technical_documentation §"Deterministic skip rule (peg-outs)" a peg-out whose
/// `source_chain_treasury_utxo_id` differs from this TM's treasury input should be skipped: only
/// the TM spending the pinned outpoint can satisfy the on-chain
/// `legit_treasury_movement_and_peg_out_produced` verifier, so a payment from any other TM can
/// never be completed — the fBTC stays locked and cancellable while the BTC is gone.
///
/// [`select_unpaid`] already prevents *repeat* payment, so this is a separate, weaker concern:
/// paying a stale-pinned request once. It is reported as a warning by default and enforced under
/// `--require-pegout-pin`, because on a bridge where requests routinely outlive the tip they were
/// created against, enforcing it means paying nobody until every request is re-created.
#[must_use]
pub fn partition_by_pin(
    requests: Vec<PegOutRequestData>,
    treasury_outpoint: &bitcoin::OutPoint,
) -> (Vec<PegOutRequestData>, Vec<PegOutRequestData>) {
    let expected = crate::cardano::tm_chain::outpoint_bytes(treasury_outpoint);
    requests
        .into_iter()
        .partition(|r| r.pinned_treasury_outpoint == expected)
}

/// Fetch every PegOut request at `pegout_address`, identified by carrying the `fbtc_unit` token
/// (`<policy_hex><asset_name_hex>`). Returns the destination scriptPubKey + pinned treasury
/// outpoint (from the datum) and the locked fBTC amount (from the value) for each, in deterministic
/// order — so two SPOs reading the same chain state build the same TM.
///
/// These are ALL open requests, including ones an earlier TM already paid (they linger until their
/// owner completes them). Pass the result through [`select_fulfillable`] with the TM's treasury
/// input before building — that is what keeps a paid request out of the next TM.
pub async fn fetch_pegout_requests(
    base_url: &str,
    project_id: &str,
    pegout_address: &str,
    fbtc_unit: &str,
) -> Result<Vec<PegOutRequestData>, String> {
    let utxos = bf_http::fetch_address_utxos(base_url, project_id, pegout_address).await?;

    // Blockfrost emits units as lowercase hex; normalise the operator-supplied unit so a
    // copy-pasted uppercase value doesn't silently match zero UTxOs (→ a TM that pays no peg-outs).
    let fbtc_unit = fbtc_unit.trim().to_ascii_lowercase();

    let mut out = Vec::new();
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
            let (destination_script_pubkey, pinned_treasury_outpoint) =
                parse_pegout_datum(&plutus)?;
            Ok(PegOutRequestData {
                destination_script_pubkey,
                amount_sat,
                pinned_treasury_outpoint,
                cardano_utxo: (utxo.tx_hash.clone(), utxo.output_index),
            })
        })();
        match request {
            Ok(req) => out.push(req),
            Err(why) => {
                eprintln!(
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
    Ok(out)
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

    fn pin(b: u8) -> [u8; 36] {
        let mut p = [b; 36];
        p[32..].copy_from_slice(&0u32.to_le_bytes());
        p
    }

    fn three_fields(spk: &[u8]) -> Vec<PlutusData> {
        vec![bytes(b"owner-auth"), bytes(spk), bytes(&pin(0xaa))]
    }

    fn request(spk: &[u8], amount_sat: u64, pinned: [u8; 36]) -> PegOutRequestData {
        PegOutRequestData {
            destination_script_pubkey: spk.to_vec(),
            amount_sat,
            pinned_treasury_outpoint: pinned,
            cardano_utxo: ("ab".repeat(32), 0),
        }
    }

    #[test]
    fn extracts_field1_and_field2_from_tag_121() {
        let d = pegout_datum(121, None, three_fields(b"\x51\x20destination"));
        let (spk, pinned) = parse_pegout_datum(&d).unwrap();
        assert_eq!(spk, b"\x51\x20destination");
        assert_eq!(pinned, pin(0xaa));
    }

    // Constructor 0 in the general tag-102 form must be accepted — it's legal Plutus data the node
    // accepts, so rejecting it would drop a completable peg-out.
    #[test]
    fn extracts_fields_from_tag_102_constructor_0() {
        let d = pegout_datum(102, Some(0), three_fields(b"\x51\x20destination"));
        let (spk, pinned) = parse_pegout_datum(&d).unwrap();
        assert_eq!(spk, b"\x51\x20destination");
        assert_eq!(pinned, pin(0xaa));
    }

    #[test]
    fn rejects_wrong_constructor_and_shape() {
        // constructor 1 (tag 122) is not a PegOutDatum
        assert!(parse_pegout_datum(&pegout_datum(122, None, three_fields(b"x"))).is_err());
        // 102 form with a non-zero constructor
        assert!(parse_pegout_datum(&pegout_datum(102, Some(1), three_fields(b"x"))).is_err());
        // wrong field count
        assert!(parse_pegout_datum(&pegout_datum(121, None, vec![bytes(b"a")])).is_err());
        // field[1] not bytes
        let bad = pegout_datum(
            121,
            None,
            vec![bytes(b"a"), pegout_datum(121, None, vec![]), bytes(b"c")],
        );
        assert!(parse_pegout_datum(&bad).is_err());
        // not a Constr at all
        assert!(parse_pegout_datum(&bytes(b"nope")).is_err());
    }

    // A pin that is not a 36-byte outpoint can never be matched by the on-chain produced verifier,
    // so the request is unfulfillable — reject at parse instead of paying BTC for it.
    #[test]
    fn rejects_pin_that_is_not_a_36_byte_outpoint() {
        let short = pegout_datum(
            121,
            None,
            vec![bytes(b"owner"), bytes(b"\x51\x20dest"), bytes(b"too-short")],
        );
        assert!(parse_pegout_datum(&short).is_err());
        // The empty pin binocular writes into PegIn datums is likewise not a peg-out pin.
        let empty = pegout_datum(
            121,
            None,
            vec![bytes(b"owner"), bytes(b"\x51\x20dest"), bytes(b"")],
        );
        assert!(parse_pegout_datum(&empty).is_err());
    }

    // --- payment-history filter ---------------------------------------------------------------

    use crate::cardano::treasury_datum::{ConfirmedTm, TmOutput, UnconfirmedTm};

    /// A Confirmed record whose output 0 is the treasury and 1.. are peg-out payments.
    fn confirmed(treasury_sat: u64, pegouts: &[(&[u8], u64)]) -> ConfirmedTm {
        let mut outputs = vec![TmOutput {
            script_pub_key: b"\x51\x20treasury".to_vec(),
            amount: treasury_sat,
        }];
        outputs.extend(pegouts.iter().map(|(spk, amount)| TmOutput {
            script_pub_key: spk.to_vec(),
            amount: *amount,
        }));
        ConfirmedTm {
            btc_txid: [0xcc; 32],
            swept_inputs: vec![],
            outputs,
        }
    }

    fn unconfirmed(inputs: Vec<bitcoin::OutPoint>, pegouts: &[(&[u8], u64)]) -> UnconfirmedTm {
        let mut outputs = vec![(
            bitcoin::Amount::from_sat(1_000),
            bitcoin::ScriptBuf::from_bytes(b"\x51\x20treasury".to_vec()),
        )];
        outputs.extend(pegouts.iter().map(|(spk, amount)| {
            (
                bitcoin::Amount::from_sat(*amount),
                bitcoin::ScriptBuf::from_bytes(spk.to_vec()),
            )
        }));
        UnconfirmedTm {
            btc_txid: "4444444444444444444444444444444444444444444444444444444444444444"
                .parse()
                .unwrap(),
            inputs,
            outputs,
            cardano_tx_hash: String::new(),
            block_time: None,
        }
    }

    const DEST_A: &[u8] = b"\x00\x14aaaaaaaaaaaaaaaaaaaa";
    const DEST_B: &[u8] = b"\x00\x14bbbbbbbbbbbbbbbbbbbb";

    // The core bug: a paid request lingers at the peg-out address until its owner completes it, so
    // the next TM must not pay it again.
    #[test]
    fn already_paid_request_is_filtered_out() {
        let records = [confirmed(500_000, &[(DEST_A, 50_000)])];
        let mut paid = PaidPegOuts::from_records(&records, std::iter::empty());
        let (unpaid, already) = select_unpaid(
            vec![
                request(DEST_A, 50_000, pin(0xaa)),
                request(DEST_B, 60_000, pin(0xaa)),
            ],
            0,
            &mut paid,
        );
        assert_eq!(unpaid.len(), 1);
        assert_eq!(unpaid[0].destination_script_pubkey, DEST_B);
        assert_eq!(already.len(), 1);
        assert_eq!(already[0].destination_script_pubkey, DEST_A);
    }

    // Multiset, not set: three identical requests with one payment recorded → exactly one is
    // filtered. A set-based filter would strand the other two's fBTC forever.
    #[test]
    fn duplicate_requests_are_filtered_one_per_recorded_payment() {
        let records = [confirmed(500_000, &[(DEST_A, 2_500), (DEST_A, 2_500)])];
        let mut paid = PaidPegOuts::from_records(&records, std::iter::empty());
        assert_eq!(paid.remaining(DEST_A, 2_500), 2);

        let (unpaid, already) = select_unpaid(
            vec![
                request(DEST_A, 2_500, pin(0xaa)),
                request(DEST_A, 2_500, pin(0xaa)),
                request(DEST_A, 2_500, pin(0xaa)),
            ],
            0,
            &mut paid,
        );
        assert_eq!(already.len(), 2, "two payments recorded → two filtered");
        assert_eq!(unpaid.len(), 1, "the third is still owed its payment");
    }

    // Output 0 is the treasury continuation, never a peg-out — counting it could mask a request
    // whose destination/amount happened to match.
    #[test]
    fn treasury_output_is_not_counted_as_a_payment() {
        let records = [confirmed(50_000, &[])];
        let paid = PaidPegOuts::from_records(&records, std::iter::empty());
        assert!(paid.is_empty());
        assert_eq!(paid.remaining(b"\x51\x20treasury", 50_000), 0);
    }

    // The TM output carries gross − per_pegout_fee, so that is the amount the datum records and the
    // amount the filter must match on.
    #[test]
    fn matching_uses_the_net_paid_amount_not_the_gross_request() {
        let records = [confirmed(500_000, &[(DEST_A, 49_000)])];
        let mut paid = PaidPegOuts::from_records(&records, std::iter::empty());
        let (unpaid, already) =
            select_unpaid(vec![request(DEST_A, 50_000, pin(0xaa))], 1_000, &mut paid);
        assert_eq!(
            already.len(),
            1,
            "50_000 gross − 1_000 fee == the 49_000 paid"
        );
        assert!(unpaid.is_empty());

        // With the wrong fee the same request looks unpaid — determinism therefore needs the fee to
        // be a consensus value across SPOs.
        let mut paid = PaidPegOuts::from_records(&records, std::iter::empty());
        let (unpaid, _) = select_unpaid(vec![request(DEST_A, 50_000, pin(0xaa))], 0, &mut paid);
        assert_eq!(unpaid.len(), 1);
    }

    // An in-flight TM's payments are already committed in signed Bitcoin bytes: not yet Confirmed,
    // but must not be paid twice.
    #[test]
    fn live_in_flight_payments_are_counted() {
        let live = unconfirmed(vec![], &[(DEST_A, 50_000)]);
        let mut paid = PaidPegOuts::from_records(&[], std::iter::once(&live));
        let (unpaid, already) =
            select_unpaid(vec![request(DEST_A, 50_000, pin(0xaa))], 0, &mut paid);
        assert_eq!(already.len(), 1);
        assert!(unpaid.is_empty());
    }

    // A request paid by NO TM stays payable even after many unrelated movements.
    #[test]
    fn unrelated_history_does_not_filter_a_fresh_request() {
        let records = [
            confirmed(500_000, &[(DEST_B, 60_000)]),
            confirmed(400_000, &[(DEST_B, 60_000)]),
        ];
        let mut paid = PaidPegOuts::from_records(&records, std::iter::empty());
        let (unpaid, already) =
            select_unpaid(vec![request(DEST_A, 50_000, pin(0xaa))], 0, &mut paid);
        assert_eq!(unpaid.len(), 1);
        assert!(already.is_empty());
    }

    #[test]
    fn partition_by_pin_splits_on_the_datum_pin() {
        let tip = bitcoin::OutPoint {
            txid: "1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            vout: 0,
        };
        let matching = crate::cardano::tm_chain::outpoint_bytes(&tip);
        let (here, elsewhere) = partition_by_pin(
            vec![
                request(DEST_A, 50_000, matching),
                request(DEST_B, 60_000, pin(0xcc)),
            ],
            &tip,
        );
        assert_eq!(here.len(), 1);
        assert_eq!(here[0].amount_sat, 50_000);
        assert_eq!(elsewhere.len(), 1);
        assert_eq!(elsewhere[0].amount_sat, 60_000);
    }
}
