//! Read PegOut requests from `peg_out.ak` UTxOs on Cardano — the SPO's spec job
//! (technical_documentation §`peg_out.ak`: "SPOs read these UTxOs to include peg-out payments
//! in the Treasury Movement transaction").
//!
//! Each PegOut UTxO carries an inline `PegOutDatum` (Aiken `Constr 0` with 3 fields:
//! `[owner_auth, source_chain_destination_address, source_chain_treasury_utxo_id]`). Field[1] is
//! the raw Bitcoin scriptPubKey the TM must pay; field[2] is the Bitcoin treasury outpoint the
//! paying TM must spend, which PINS this peg-out to exactly one possible TM (see below); the
//! locked fBTC quantity in the UTxO value is the GROSS peg-out amount. The destination, the pin,
//! and the gross amount all come from on-chain state, never from the operator.
//!
//! ## The treasury pin (field[2]) is what makes a peg-out payable ONCE
//!
//! `source_chain_treasury_utxo_id` is the 36-byte Bitcoin outpoint form `prev_txid(32, internal
//! byte order) ++ vout(4, LE)` — the same encoding as `swept_peg_in_utxo_ids`, so
//! [`crate::cardano::treasury_datum::outpoint_from_swept_key`] decodes it. It names the treasury
//! UTxO the paying TM must spend, and BOTH on-chain completion paths compare against it:
//!
//! - `CompletePegOut` delegates to the `legit_treasury_movement_and_peg_out_produced` verifier
//!   (binocular `PegOutProducedVerifier`), which proves from the raw TM bytes that the TM
//!   **spends this outpoint** AND pays the destination the amount.
//! - `Cancel` delegates to the mirror `..._not_produced` verifier: the TM spending this outpoint
//!   contains NO such payment, so the fBTC is refunded. NOTE: binocular's
//!   `PegOutNotProducedVerifier` is currently a deliberate `fail(...)` stub, so on the deployed
//!   demo bridge `Cancel` is DISABLED — a skipped peg-out's fBTC cannot be reclaimed yet.
//!
//! Since Bitcoin spends each outpoint exactly once, the pin admits at most one TM per request.
//! A TM that pays a peg-out whose pin is NOT its own treasury input therefore sends BTC that can
//! never be completed — and with `Cancel` stubbed the locked fBTC is stuck too, so the payout is
//! pure treasury loss (once the refund path ships, it instead becomes a refund the withdrawer
//! collects ON TOP of the BTC). Conversely, re-including an already-paid request in a LATER TM
//! (whose treasury input is by construction a different outpoint) pays it twice for one fBTC burn.
//! Both are prevented by the single skip condition in
//! [`crate::bitcoin::tm_builder::build_tm`]: include a peg-out iff its pin equals this TM's
//! treasury input. Spec: technical_documentation.md §"Shared state reference" + §"Deterministic
//! skip rule (peg-outs)".
//!
//! The BTC output does NOT pay the gross amount in full: per technical_documentation §"Treasury
//! Movement" ("Amounts and fees"), each peg-out output = gross amount − a fixed per-peg-out
//! PROTOCOL fee (covering the miner-fee share + protocol operating costs), and the treasury change
//! absorbs the Bitcoin miner fee. The fee must be a protocol-wide parameter so every SPO builds
//! byte-identical TM bytes (FROST determinism) — see the fee-source WI and technical_questions.md.
//! The deduction is applied downstream in `bitcoin::tm_builder::build_tm`; this module only reads
//! the gross amount + destination.

use bitcoin::OutPoint;
use pallas_primitives::PlutusData;

use crate::cardano::bf_http;
use crate::cardano::plutus;
use crate::cardano::tm_chain::outpoint_bytes;
use crate::cardano::treasury_datum::outpoint_from_swept_key;

/// A peg-out the SPO must fulfil in the TM: pay `destination_script_pubkey` the GROSS
/// `amount_sat` minus the per-peg-out protocol fee (the fee deduction happens in
/// `bitcoin::tm_builder::build_tm`, not here).
#[derive(Debug, Clone)]
pub struct PegOutRequestData {
    pub destination_script_pubkey: Vec<u8>,
    /// Gross peg-out amount (the locked fBTC quantity); the BTC output pays this minus the
    /// per-peg-out protocol fee.
    pub amount_sat: u64,
    /// The treasury outpoint this request pins the paying TM to (datum field[2]). `build_tm`
    /// includes the peg-out ONLY if this equals the TM's treasury input — see the module docs.
    pub pinned_treasury_outpoint: OutPoint,
}

/// The `PegOutDatum` record fields — constructor 0, exactly 3 fields.
///
/// Constructor 0 is accepted in BOTH plutus-core encodings — the compact tag 121 form and the
/// general tag-102 + `any_constructor` form — because the user controls the datum bytes at lock
/// time and a Haskell node accepts either; rejecting the 102 form would drop a legitimate,
/// completable peg-out (the sibling registry/treasury decoders already accept both).
fn pegout_datum_fields(data: &PlutusData) -> Result<&[PlutusData], String> {
    let fields = plutus::constr_fields(data, 0).map_err(|e| format!("PegOutDatum: {e}"))?;
    if fields.len() != 3 {
        return Err(format!(
            "PegOutDatum: expected 3 fields, got {}",
            fields.len()
        ));
    }
    Ok(fields)
}

/// Extract `source_chain_destination_address` (field[1]) from a `PegOutDatum` — the raw Bitcoin
/// scriptPubKey the TM must pay.
pub fn extract_destination_spk(data: &PlutusData) -> Result<Vec<u8>, String> {
    let fields = pegout_datum_fields(data)?;
    plutus::field_bytes(fields, 1).map_err(|_| {
        "PegOutDatum: field[1] (source_chain_destination_address) is not BoundedBytes".to_string()
    })
}

/// Extract `source_chain_treasury_utxo_id` (field[2]) from a `PegOutDatum` — the treasury outpoint
/// the paying TM must spend, encoded as the 36-byte Bitcoin internal form `prev_txid(32, internal
/// byte order) ++ vout(4, LE)` (binocular `PegOutRequestCommand` writes exactly this; its
/// `PegOutProducedVerifier` memcmps it against the raw TM's 36-byte prevouts).
///
/// A field[2] that is not a 36-byte outpoint is an ERROR, not a pass-through: it can never equal
/// any TM's treasury input, so the request is unpayable and the caller must skip it rather than
/// pay a destination whose completion proof can never be built.
pub fn extract_pinned_treasury_outpoint(data: &PlutusData) -> Result<OutPoint, String> {
    let fields = pegout_datum_fields(data)?;
    let raw = plutus::field_bytes(fields, 2).map_err(|_| {
        "PegOutDatum: field[2] (source_chain_treasury_utxo_id) is not BoundedBytes".to_string()
    })?;
    outpoint_from_swept_key(&raw).ok_or_else(|| {
        format!(
            "PegOutDatum: field[2] (source_chain_treasury_utxo_id) is {} bytes, expected a \
             36-byte outpoint (txid(32, internal) ++ vout(4, LE))",
            raw.len()
        )
    })
}

/// The result of scanning the peg-out address: the requests a TM can consider, plus how many
/// fBTC-bearing UTxOs were dropped as undecodable.
///
/// `malformed` exists so operator-facing counts don't lie. These UTxOs are real pending
/// withdrawals that no TM can ever pay (see [`fetch_pegout_requests`]), so reporting only
/// `requests.len()` would print "0 peg-outs" while fBTC sits stuck at the script address.
#[derive(Debug, Clone, Default)]
pub struct PegOutScan {
    pub requests: Vec<PegOutRequestData>,
    pub malformed: usize,
}

/// Fetch every PegOut request at `pegout_address`, identified by carrying the `fbtc_unit` token
/// (`<policy_hex><asset_name_hex>`). Returns the destination scriptPubKey + pinned treasury
/// outpoint (from the datum) and the locked fBTC amount (from the value) for each, in deterministic
/// scriptPubKey order — so two SPOs reading the same chain state build the same TM.
///
/// `requests` holds EVERY well-formed pending request regardless of which treasury outpoint it
/// pins; filtering to the ones this TM can actually fulfil is `build_tm`'s job (it owns the
/// treasury input and the whole deterministic skip rule), so both the CLI and daemon paths get the
/// filter from one place. UTxOs whose datum cannot be decoded at all — including a
/// `source_chain_treasury_utxo_id` that is not a 36-byte outpoint — are counted in `malformed`
/// rather than returned, because no treasury input can ever match them.
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
            let destination_script_pubkey = extract_destination_spk(&plutus)?;
            let pinned_treasury_outpoint = extract_pinned_treasury_outpoint(&plutus)?;
            Ok(PegOutRequestData {
                destination_script_pubkey,
                amount_sat,
                pinned_treasury_outpoint,
            })
        })();
        match request {
            Ok(req) => out.push(req),
            Err(why) => {
                malformed += 1;
                eprintln!(
                    "[pegout] skipping malformed peg-out UTxO {}#{}: {why}",
                    utxo.tx_hash, utxo.output_index
                );
            }
        }
    }

    // Total order over the whole request tuple — the pin is the final tiebreaker so two requests
    // sharing a destination AND amount still order identically for every SPO (a partial order
    // would leave the residual order to Blockfrost's UTxO listing, which is not a consensus
    // input). Unlike in `build_tm`, the pin key is NOT constant here: this runs before any
    // filtering, so requests pinned to different treasuries coexist.
    out.sort_by(|a, b| {
        a.destination_script_pubkey
            .cmp(&b.destination_script_pubkey)
            .then(a.amount_sat.cmp(&b.amount_sat))
            .then(
                outpoint_bytes(&a.pinned_treasury_outpoint)
                    .cmp(&outpoint_bytes(&b.pinned_treasury_outpoint)),
            )
    });
    Ok(PegOutScan {
        requests: out,
        malformed,
    })
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

    /// A NON-palindromic 32-byte txid in internal order: `byte` everywhere except a
    /// distinct first and last byte. Uniform-byte txids (`[b; 32]`) are useless here
    /// — they are invariant under reversal, so a decoder that flipped the txid would
    /// pass every assertion. That flip is the one mistake this encoding punishes
    /// silently (it would skip 100% of peg-outs), so every pin fixture must be
    /// asymmetric.
    fn pin_txid_bytes(byte: u8) -> [u8; 32] {
        let mut t = [byte; 32];
        t[0] = 0x01;
        t[31] = 0xFE;
        t
    }

    /// A valid 36-byte pin: txid (internal order) then vout as 4 LE bytes.
    fn pin_bytes(byte: u8, vout: u32) -> Vec<u8> {
        let mut k = pin_txid_bytes(byte).to_vec();
        k.extend_from_slice(&vout.to_le_bytes());
        k
    }

    fn pin_outpoint(byte: u8, vout: u32) -> OutPoint {
        use bitcoin::hashes::Hash;
        OutPoint {
            txid: bitcoin::Txid::from_byte_array(pin_txid_bytes(byte)),
            vout,
        }
    }

    fn three_fields(spk: &[u8]) -> Vec<PlutusData> {
        three_fields_pinned(spk, &pin_bytes(0xAB, 0))
    }

    fn three_fields_pinned(spk: &[u8], pin: &[u8]) -> Vec<PlutusData> {
        vec![bytes(b"owner-auth"), bytes(spk), bytes(pin)]
    }

    #[test]
    fn extracts_field1_from_tag_121() {
        let d = pegout_datum(121, None, three_fields(b"\x51\x20destination"));
        assert_eq!(extract_destination_spk(&d).unwrap(), b"\x51\x20destination");
    }

    // Constructor 0 in the general tag-102 form must be accepted — it's legal Plutus data the node
    // accepts, so rejecting it would drop a completable peg-out.
    #[test]
    fn extracts_field1_from_tag_102_constructor_0() {
        let d = pegout_datum(102, Some(0), three_fields(b"\x51\x20destination"));
        assert_eq!(extract_destination_spk(&d).unwrap(), b"\x51\x20destination");
    }

    #[test]
    fn rejects_wrong_constructor_and_shape() {
        // constructor 1 (tag 122) is not a PegOutDatum
        assert!(extract_destination_spk(&pegout_datum(122, None, three_fields(b"x"))).is_err());
        // 102 form with a non-zero constructor
        assert!(extract_destination_spk(&pegout_datum(102, Some(1), three_fields(b"x"))).is_err());
        // wrong field count
        assert!(extract_destination_spk(&pegout_datum(121, None, vec![bytes(b"a")])).is_err());
        // field[1] not bytes
        let bad = pegout_datum(
            121,
            None,
            vec![bytes(b"a"), pegout_datum(121, None, vec![]), bytes(b"c")],
        );
        assert!(extract_destination_spk(&bad).is_err());
        // not a Constr at all
        assert!(extract_destination_spk(&bytes(b"nope")).is_err());
    }

    // --- field[2]: the treasury pin ---

    // The pin decodes as txid(32, internal byte order) ++ vout(4, LE) — the same
    // encoding binocular's `PegOutRequestCommand` writes and its on-chain
    // `PegOutProducedVerifier` memcmps against the raw TM's prevouts. Getting the
    // vout endianness or the txid order wrong would silently skip every peg-out.
    #[test]
    fn extracts_pin_as_txid_internal_plus_vout_le() {
        let d = pegout_datum(
            121,
            None,
            three_fields_pinned(b"\x51\x20dest", &pin_bytes(0xCD, 7)),
        );
        assert_eq!(
            extract_pinned_treasury_outpoint(&d).unwrap(),
            pin_outpoint(0xCD, 7)
        );
    }

    // The assertion above compares against an outpoint built from the SAME helper,
    // so it would still pass if the decoder and the fixture both reversed the txid.
    // Anchor the byte order independently: against the DISPLAY hex, which is the
    // reverse of the on-the-wire bytes. This is the assertion that actually pins
    // heimdall to binocular's `txid.hexToBytes.reverse ++ voutLE`.
    #[test]
    fn pin_txid_bytes_are_the_reverse_of_the_display_hex() {
        // Display hex ending in `00` ⇒ internal byte 0 is 0x00, and internal byte
        // 31 is the leading display byte 0x11.
        let display = "1111111111111111111111111111111111111111111111111111111111111100";
        let expected: bitcoin::Txid = display.parse().unwrap();

        let mut wire = [0x11u8; 32];
        wire[0] = 0x00; // internal order starts at the LAST display byte pair
        let mut pin = wire.to_vec();
        pin.extend_from_slice(&3u32.to_le_bytes());

        let d = pegout_datum(121, None, three_fields_pinned(b"\x51\x20dest", &pin));
        let got = extract_pinned_treasury_outpoint(&d).unwrap();
        assert_eq!(
            got.txid, expected,
            "datum bytes are internal order, not display"
        );
        assert_eq!(got.vout, 3);
        // And the display form really is the reverse — proving the two differ, so
        // the assertion above is not vacuous.
        assert_eq!(got.txid.to_string(), display);
        assert_ne!(wire.to_vec(), hex::decode(display).unwrap());
    }

    #[test]
    fn extracts_pin_from_tag_102_constructor_0() {
        let d = pegout_datum(
            102,
            Some(0),
            three_fields_pinned(b"\x51\x20dest", &pin_bytes(0x01, 0)),
        );
        assert_eq!(
            extract_pinned_treasury_outpoint(&d).unwrap(),
            pin_outpoint(0x01, 0)
        );
    }

    // A pin that is not exactly 36 bytes can never equal any TM's treasury input,
    // so the request is unpayable — reject it here (which makes `fetch` skip the
    // UTxO) rather than let a request through with no usable pin.
    #[test]
    fn rejects_pin_of_wrong_length() {
        for pin in [
            vec![],                       // empty
            vec![0xAB; 32],               // txid only, no vout
            vec![0xAB; 35],               // one byte short
            vec![0xAB; 37],               // one byte long
            b"treasury-utxo-id".to_vec(), // a human-readable placeholder
        ] {
            let d = pegout_datum(121, None, three_fields_pinned(b"\x51\x20dest", &pin));
            assert!(
                extract_pinned_treasury_outpoint(&d).is_err(),
                "{} -byte pin must be rejected",
                pin.len()
            );
        }
    }

    // field[2] not BoundedBytes (e.g. a nested Constr) is a decode error, not a panic.
    #[test]
    fn rejects_pin_that_is_not_bytes() {
        let d = pegout_datum(
            121,
            None,
            vec![
                bytes(b"owner-auth"),
                bytes(b"\x51\x20dest"),
                pegout_datum(121, None, vec![]),
            ],
        );
        assert!(extract_pinned_treasury_outpoint(&d).is_err());
    }

    // The pin survives a full round-trip through `tm_chain::outpoint_bytes` — the
    // encoder `build_tm`'s treasury input is compared with — so a pin read from a
    // datum compares equal to a locally-built treasury outpoint. (Round-tripping
    // alone cannot catch a consistent double-reversal; that is what
    // `pin_txid_bytes_are_the_reverse_of_the_display_hex` is for.)
    #[test]
    fn pin_round_trips_through_the_36_byte_encoding() {
        let op = pin_outpoint(0x9F, 3);
        assert_eq!(outpoint_from_swept_key(&outpoint_bytes(&op)), Some(op));
        // And the datum path agrees with the encoder.
        let d = pegout_datum(
            121,
            None,
            three_fields_pinned(b"\x51\x20dest", &outpoint_bytes(&op)),
        );
        assert_eq!(extract_pinned_treasury_outpoint(&d).unwrap(), op);
    }
}
