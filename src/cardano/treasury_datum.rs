//! Parse the treasury oracle datum.
//!
//! The treasury UTxO on Cardano carries an inline datum wrapping the
//! most recent Bitcoin treasury movement transaction:
//!
//! ```text
//! Constr(0, [
//!     BoundedBytes(raw_btc_tx),   -- full signed Bitcoin transaction
//! ])
//! ```
//!
//! We deserialize the BTC tx to find the treasury output (output 0),
//! which gives us the outpoint (txid:0) and value. The remaining
//! `TreasuryUtxo` fields (leaf keys, CSV timeout, fee params) are not
//! encoded in the datum — they come from `TreasuryConfig`.

use bitcoin::consensus::deserialize;
use bitcoin::{Amount, OutPoint, Transaction};
use pallas_primitives::PlutusData;

use crate::epoch::traits::TreasuryUtxo;

/// Off-chain configuration for treasury parameters not stored in the
/// on-chain datum. These are protocol constants for a given epoch.
#[derive(Debug, Clone)]
pub struct TreasuryConfig {
    pub y_67: bitcoin::key::UntweakedPublicKey,
    pub y_fed: bitcoin::key::UntweakedPublicKey,
    pub federation_csv_blocks: u32,
    pub fee_rate_sat_per_vb: u64,
    pub per_pegout_fee: Amount,
}

#[derive(Debug)]
pub enum TreasuryDatumError {
    NotConstr,
    WrongTag(u64),
    FieldCount { expected: usize, got: usize },
    NotBytes(String),
    BtcDeserialize(String),
    NoTreasuryOutput,
}

impl std::fmt::Display for TreasuryDatumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConstr => write!(f, "expected Constr(0, [...])"),
            Self::WrongTag(t) => write!(f, "expected Constr tag 121, got {t}"),
            Self::FieldCount { expected, got } => {
                write!(f, "expected {expected} field(s), got {got}")
            }
            Self::NotBytes(msg) => write!(f, "field[0]: expected BoundedBytes, {msg}"),
            Self::BtcDeserialize(msg) => write!(f, "BTC tx deserialize: {msg}"),
            Self::NoTreasuryOutput => write!(f, "BTC tx has no outputs"),
        }
    }
}

impl std::error::Error for TreasuryDatumError {}

/// Build a `TreasuryUtxo` directly from raw BTC transaction bytes.
///
/// This is the primary parse path used by the Blockfrost chain, which
/// fetches the datum via the JSON endpoint (avoiding CBOR chunking
/// issues) and hands us the raw bytes.
pub fn treasury_from_btc_tx_bytes(
    tx_bytes: &[u8],
    config: &TreasuryConfig,
) -> Result<TreasuryUtxo, TreasuryDatumError> {
    let tx: Transaction = deserialize(tx_bytes)
        .map_err(|e| TreasuryDatumError::BtcDeserialize(e.to_string()))?;

    let out = tx.output.first().ok_or(TreasuryDatumError::NoTreasuryOutput)?;
    let txid = tx.compute_txid();

    Ok(TreasuryUtxo {
        outpoint: OutPoint { txid, vout: 0 },
        value: out.value,
        y_67: config.y_67,
        y_fed: config.y_fed,
        federation_csv_blocks: config.federation_csv_blocks,
        fee_rate_sat_per_vb: config.fee_rate_sat_per_vb,
        per_pegout_fee: config.per_pegout_fee,
    })
}

/// Extract the raw BTC transaction bytes from the datum's single
/// `BoundedBytes` field.
fn extract_btc_tx_bytes(data: &PlutusData) -> Result<Vec<u8>, TreasuryDatumError> {
    let (tag, fields) = match data {
        PlutusData::Constr(constr) => (constr.tag, &constr.fields),
        _ => return Err(TreasuryDatumError::NotConstr),
    };

    // Constr(0, ...) in PlutusData CBOR uses tag 121.
    if tag != 121 {
        return Err(TreasuryDatumError::WrongTag(tag));
    }
    if fields.len() != 1 {
        return Err(TreasuryDatumError::FieldCount {
            expected: 1,
            got: fields.len(),
        });
    }

    match &fields[0] {
        PlutusData::BoundedBytes(b) => Ok(b.clone().into()),
        other => Err(TreasuryDatumError::NotBytes(format!(
            "got {:?}",
            std::mem::discriminant(other)
        ))),
    }
}

/// Decode the on-chain treasury datum into a `TreasuryUtxo`.
///
/// The datum contains the raw BTC treasury movement transaction.
/// Output 0 is the treasury output — its value and the tx's txid give
/// us the outpoint. The remaining fields come from `config`.
pub fn parse_treasury_datum(
    data: &PlutusData,
    config: &TreasuryConfig,
) -> Result<TreasuryUtxo, TreasuryDatumError> {
    let tx_bytes = extract_btc_tx_bytes(data)?;
    let tx: Transaction = deserialize(&tx_bytes)
        .map_err(|e| TreasuryDatumError::BtcDeserialize(e.to_string()))?;

    let out = tx.output.first().ok_or(TreasuryDatumError::NoTreasuryOutput)?;
    let txid = tx.compute_txid();

    Ok(TreasuryUtxo {
        outpoint: OutPoint { txid, vout: 0 },
        value: out.value,
        y_67: config.y_67,
        y_fed: config.y_fed,
        federation_csv_blocks: config.federation_csv_blocks,
        fee_rate_sat_per_vb: config.fee_rate_sat_per_vb,
        per_pegout_fee: config.per_pegout_fee,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_primitives::conway::Constr;
    use pallas_primitives::{BoundedBytes, MaybeIndefArray};

    fn demo_config() -> TreasuryConfig {
        let secp = bitcoin::key::Secp256k1::new();
        let y_67 = bitcoin::key::UntweakedPublicKey::from_slice(
            &bitcoin::secp256k1::SecretKey::from_slice(&[0x67u8; 32])
                .unwrap()
                .x_only_public_key(&secp)
                .0
                .serialize(),
        )
        .unwrap();
        let y_fed = bitcoin::key::UntweakedPublicKey::from_slice(
            &bitcoin::secp256k1::SecretKey::from_slice(&[0xFEu8; 32])
                .unwrap()
                .x_only_public_key(&secp)
                .0
                .serialize(),
        )
        .unwrap();
        TreasuryConfig {
            y_67,
            y_fed,
            federation_csv_blocks: 144,
            fee_rate_sat_per_vb: 1,
            per_pegout_fee: Amount::from_sat(1_000),
        }
    }

    /// BTC tx hex extracted from the preprod treasury datum (tx 047c71ad...).
    /// This is the `bytes` field from Blockfrost's JSON datum endpoint.
    const PREPROD_BTC_TX_HEX: &str = "02000000000101f4780792094629c78ba9d82a41a6c5f6f66aa44fa9c9717818e3e2b51a401c130000000000fdffffff028096980000000000225120b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f28540e556d2901000000225120dcd898aeb18c66dcb701ede4641122e4a20d38eec1de6a1b49084d4569eed3730247304402200b053d4ee8b2402019b7168d6058360ba614b426c1b04b736ec01db844a18ffc02205f1fe66232bfeb9b6677cfdddfd49af33cf55a133ae0795b09dd85105f8e2c7d012103046eb15ca36697d619d908a255c1328e262aecb43043dd746cefce79b1bea99f79000000";

    #[test]
    fn parse_preprod_btc_tx() {
        let tx_bytes = hex::decode(PREPROD_BTC_TX_HEX).unwrap();
        let config = demo_config();
        let treasury = treasury_from_btc_tx_bytes(&tx_bytes, &config).unwrap();

        assert_eq!(treasury.value, Amount::from_sat(10_000_000));
        assert_eq!(treasury.outpoint.vout, 0);
        assert_eq!(treasury.federation_csv_blocks, 144);
        assert_eq!(treasury.fee_rate_sat_per_vb, 1);
    }

    #[test]
    fn roundtrip_through_cbor() {
        // Build a minimal BTC tx, wrap it in a datum, CBOR-encode, decode, parse.
        let btc_tx_hex = "02000000000101f4780792094629c78ba9d82a41a6c5f6f66aa44fa9c9717818e3e2b51a401c130000000000fdffffff028096980000000000225120b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f28540e556d2901000000225120dcd898aeb18c66dcb701ede4641122e4a20d38eec1de6a1b49084d4569eed3730247304402200b053d4ee8b2402019b7168d6058360ba614b426c1b04b736ec01db844a18ffc02205f1fe66232bfeb9b6677cfdddfd49af33cf55a133ae0795b09dd85105f8e2c7d012103046eb15ca36697d619d908a255c1328e262aecb43043dd746cefce79b1bea99f79000000";
        let tx_bytes = hex::decode(btc_tx_hex).unwrap();

        let datum = PlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![PlutusData::BoundedBytes(
                BoundedBytes::from(tx_bytes),
            )]),
        });

        let cbor = pallas_codec::minicbor::to_vec(&datum).unwrap();
        let decoded: PlutusData = pallas_codec::minicbor::decode(&cbor).unwrap();
        let config = demo_config();
        let treasury = parse_treasury_datum(&decoded, &config).unwrap();
        assert_eq!(treasury.value, Amount::from_sat(10_000_000));
    }
}
