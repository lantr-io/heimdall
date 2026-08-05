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
//!  - [`PaidPegOuts`] + [`select_unpaid`] cover the window before a payment reaches the trie
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

use std::collections::HashMap;

use pallas_primitives::PlutusData;

use crate::cardano::bf_http;
use crate::cardano::plutus;

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
/// The match is on the amount the TM actually pays — `gross − per_pegout_fee`, read from each
/// request's OWN datum — because that is what a Confirmed datum records. A request whose gross does
/// not exceed its fee has no payable amount at all; it is left in `unpaid` and dropped downstream by
/// `build_tm` (which owns the dust and non-standard-script skips), so the two skip rules stay in
/// one place.
///
/// Deterministic for FROST: the outcome depends only on the Cardano snapshot, and requests sharing
/// one `(destination, net amount)` key produce byte-identical outputs, so *which* of them is
/// filtered cannot change the TM bytes.
#[must_use]
pub fn select_unpaid(
    requests: Vec<PegOutRequestData>,
    paid: &mut PaidPegOuts,
) -> (Vec<PegOutRequestData>, Vec<PegOutRequestData>) {
    let mut unpaid = Vec::new();
    let mut already_paid = Vec::new();
    for r in requests {
        let net = r.net_sat();
        if net > 0 && paid.claim(&r.destination_script_pubkey, net) {
            already_paid.push(r);
        } else {
            unpaid.push(r);
        }
    }
    (unpaid, already_paid)
}

/// Fetch every PegOut request at `pegout_address`, identified by carrying the `fbtc_unit` token
/// (`<policy_hex><asset_name_hex>`). Returns the destination scriptPubKey, the datum-pinned fee and
/// `created`, the request identity (`por_id`, `outpoint`), and the locked fBTC amount (from the
/// value) for each, in deterministic order — so two SPOs reading the same chain state build the
/// same TM.
///
/// These are ALL open requests, including ones an earlier TM already paid (they linger until their
/// owner completes them). Pass the result through [`select_unpaid`] before building, and hand
/// `build_tm` the completed-peg-outs trie — between them that is what keeps a paid request out of
/// the next TM.
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
        }
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
            vec![request(DEST_A, 50_000, 0), request(DEST_B, 60_000, 0)],
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
                request(DEST_A, 2_500, 0),
                request(DEST_A, 2_500, 0),
                request(DEST_A, 2_500, 0),
            ],
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
    // amount the filter must match on. The fee is now per-REQUEST, read from its own datum.
    #[test]
    fn matching_uses_the_net_paid_amount_not_the_gross_request() {
        let records = [confirmed(500_000, &[(DEST_A, 49_000)])];
        let mut paid = PaidPegOuts::from_records(&records, std::iter::empty());
        let (unpaid, already) = select_unpaid(vec![request(DEST_A, 50_000, 1_000)], &mut paid);
        assert_eq!(
            already.len(),
            1,
            "50_000 gross − 1_000 fee == the 49_000 paid"
        );
        assert!(unpaid.is_empty());

        // A request carrying a DIFFERENT pinned fee pays a different net, so the same history
        // does not account for it. This is why the fee must come from the datum: it is what makes
        // the filter agree across SPOs without a shared config value.
        let mut paid = PaidPegOuts::from_records(&records, std::iter::empty());
        let (unpaid, _) = select_unpaid(vec![request(DEST_A, 50_000, 0)], &mut paid);
        assert_eq!(unpaid.len(), 1);
    }

    // Two requests to one destination with different pinned fees but the same NET amount are
    // interchangeable to the filter — exactly one is claimed per recorded payment.
    #[test]
    fn requests_with_different_fees_but_equal_net_share_one_credit() {
        let records = [confirmed(500_000, &[(DEST_A, 49_000)])];
        let mut paid = PaidPegOuts::from_records(&records, std::iter::empty());
        let (unpaid, already) = select_unpaid(
            vec![request(DEST_A, 50_000, 1_000), request(DEST_A, 49_500, 500)],
            &mut paid,
        );
        assert_eq!(already.len(), 1);
        assert_eq!(unpaid.len(), 1);
    }

    // An in-flight TM's payments are already committed in signed Bitcoin bytes: not yet Confirmed,
    // but must not be paid twice.
    #[test]
    fn live_in_flight_payments_are_counted() {
        let live = unconfirmed(vec![], &[(DEST_A, 50_000)]);
        let mut paid = PaidPegOuts::from_records(&[], std::iter::once(&live));
        let (unpaid, already) = select_unpaid(vec![request(DEST_A, 50_000, 0)], &mut paid);
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
        let (unpaid, already) = select_unpaid(vec![request(DEST_A, 50_000, 0)], &mut paid);
        assert_eq!(unpaid.len(), 1);
        assert!(already.is_empty());
    }
}
