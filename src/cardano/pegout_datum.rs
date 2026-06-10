//! Read PegOut requests from `peg_out.ak` UTxOs on Cardano — the SPO's spec job
//! (technical_documentation §`peg_out.ak`: "SPOs read these UTxOs to include peg-out payments
//! in the Treasury Movement transaction").
//!
//! Each PegOut UTxO carries an inline `PegOutDatum` (Aiken `Constr 0` with 3 fields:
//! `[owner_auth, source_chain_destination_address, source_chain_treasury_utxo_id]`). Field[1] is
//! the raw Bitcoin scriptPubKey the TM must pay; the locked fBTC quantity in the UTxO value is the
//! amount (the protocol pays the destination exactly this amount — no per-pegout fee). The
//! destination + amount come from on-chain state, never from the operator.

use pallas_primitives::PlutusData;

use crate::cardano::bf_http;

/// A peg-out the SPO must fulfil in the TM: pay `destination_script_pubkey` exactly `amount_sat`.
#[derive(Debug, Clone)]
pub struct PegOutRequestData {
    pub destination_script_pubkey: Vec<u8>,
    pub amount_sat: u64,
}

/// Extract `source_chain_destination_address` (field[1]) from a `PegOutDatum`. The datum is the
/// Aiken `PegOutDatum` record — Constr 0 (CBOR tag 121), exactly 3 fields; only field[1] is read.
pub fn extract_destination_spk(data: &PlutusData) -> Result<Vec<u8>, String> {
    let (tag, fields) = match data {
        PlutusData::Constr(c) => (c.tag, &c.fields),
        _ => return Err("PegOutDatum: top level not Constr".into()),
    };
    if tag != 121 {
        return Err(format!(
            "PegOutDatum: expected Constr 0 (tag 121), got tag {tag}"
        ));
    }
    if fields.len() != 3 {
        return Err(format!(
            "PegOutDatum: expected 3 fields, got {}",
            fields.len()
        ));
    }
    match &fields[1] {
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

    let mut out = Vec::new();
    for utxo in utxos {
        // The peg-out amount is the locked fBTC quantity in the value (no datum field for it).
        let amount_sat: u64 = match utxo.amount.iter().find(|a| a.unit == fbtc_unit) {
            Some(a) => a
                .quantity
                .parse()
                .map_err(|e| format!("bad fBTC quantity '{}': {e}", a.quantity))?,
            None => continue, // no fBTC under this UTxO — not a peg-out request
        };
        let Some(datum_hex) = &utxo.inline_datum else {
            continue;
        };
        let datum_cbor = hex::decode(datum_hex).map_err(|e| format!("pegout datum hex: {e}"))?;
        let plutus: PlutusData = pallas_codec::minicbor::decode(&datum_cbor)
            .map_err(|e| format!("pegout datum cbor: {e}"))?;
        let destination_script_pubkey = extract_destination_spk(&plutus)?;
        out.push(PegOutRequestData {
            destination_script_pubkey,
            amount_sat,
        });
    }

    out.sort_by(|a, b| {
        a.destination_script_pubkey
            .cmp(&b.destination_script_pubkey)
            .then(a.amount_sat.cmp(&b.amount_sat))
    });
    Ok(out)
}
