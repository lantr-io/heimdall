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
//! The BTC output does NOT pay the gross amount in full: per technical_documentation §"Treasury
//! Movement" ("Amounts and fees"), each peg-out output = gross amount − a fixed per-peg-out
//! PROTOCOL fee (covering the miner-fee share + protocol operating costs), and the treasury change
//! absorbs the Bitcoin miner fee. The fee must be a protocol-wide parameter so every SPO builds
//! byte-identical TM bytes (FROST determinism) — see the fee-source WI and technical_questions.md.
//! The deduction is applied downstream in `bitcoin::tm_builder::build_tm`; this module only reads
//! the gross amount + destination.

use pallas_primitives::PlutusData;

use crate::cardano::bf_http;

/// A peg-out the SPO must fulfil in the TM: pay `destination_script_pubkey` the GROSS
/// `amount_sat` minus the per-peg-out protocol fee (the fee deduction happens in
/// `bitcoin::tm_builder::build_tm`, not here).
#[derive(Debug, Clone)]
pub struct PegOutRequestData {
    pub destination_script_pubkey: Vec<u8>,
    /// Gross peg-out amount (the locked fBTC quantity); the BTC output pays this minus the
    /// per-peg-out protocol fee.
    pub amount_sat: u64,
}

/// Extract `source_chain_destination_address` (field[1]) from a `PegOutDatum`. The datum is the
/// Aiken `PegOutDatum` record — constructor 0, exactly 3 fields; only field[1] is read.
///
/// Constructor 0 is accepted in BOTH plutus-core encodings — the compact tag 121 form and the
/// general tag-102 + `any_constructor` form — because the user controls the datum bytes at lock
/// time and a Haskell node accepts either; rejecting the 102 form would drop a legitimate,
/// completable peg-out (the sibling registry/treasury decoders already accept both).
pub fn extract_destination_spk(data: &PlutusData) -> Result<Vec<u8>, String> {
    let c = match data {
        PlutusData::Constr(c) => c,
        _ => return Err("PegOutDatum: top level not Constr".into()),
    };
    let ctor = match c.tag {
        121..=127 => c.tag - 121,
        102 => c.any_constructor.unwrap_or(u64::MAX),
        other => return Err(format!("PegOutDatum: not a Constr tag ({other})")),
    };
    if ctor != 0 {
        return Err(format!("PegOutDatum: expected constructor 0, got {ctor}"));
    }
    if c.fields.len() != 3 {
        return Err(format!(
            "PegOutDatum: expected 3 fields, got {}",
            c.fields.len()
        ));
    }
    match &c.fields[1] {
        PlutusData::BoundedBytes(b) => Ok(b.clone().into()),
        _ => Err(
            "PegOutDatum: field[1] (source_chain_destination_address) is not BoundedBytes".into(),
        ),
    }
}

/// Fetch every PegOut request at `pegout_address`, identified by carrying the `fbtc_unit` token
/// (`<policy_hex><asset_name_hex>`). Returns the destination scriptPubKey (from the datum) and the
/// locked fBTC amount (from the value) for each, in deterministic scriptPubKey order — so two SPOs
/// reading the same chain state build the same TM.
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
            let destination_script_pubkey = extract_destination_spk(&plutus)?;
            Ok(PegOutRequestData {
                destination_script_pubkey,
                amount_sat,
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

    out.sort_by(|a, b| {
        a.destination_script_pubkey
            .cmp(&b.destination_script_pubkey)
            .then(a.amount_sat.cmp(&b.amount_sat))
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

    fn three_fields(spk: &[u8]) -> Vec<PlutusData> {
        vec![bytes(b"owner-auth"), bytes(spk), bytes(b"treasury-utxo-id")]
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
}
