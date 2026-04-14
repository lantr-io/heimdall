//! Build and submit Cardano transactions that update the treasury
//! oracle datum.
//!
//! After the FROST signing round produces a witnessed Bitcoin TM
//! transaction, the leader publishes it back to the Cardano treasury
//! oracle by **creating a new UTxO** at the treasury address with the
//! signed BTC tx as an inline datum:
//!
//! ```text
//! Constr(0, [BoundedBytes(signed_btc_tx)])
//! ```
//!
//! Constructor 0 = unconfirmed TM tx (confirmed = constructor 1, set
//! by Binocular after Bitcoin inclusion proof). The new UTxO also
//! carries 1 freshly-minted treasury marker token (using the Plutus V3
//! always-succeeds minting policy `ALWAYS_OK_PLUTUS_CBOR_HEX`).
//!
//! The old oracle UTxO is NOT spent — old confirmed UTxOs are needed
//! for minting fBTC proofs. The most recent UTxO at the treasury
//! address (with a datum) is always used as the current oracle.

use pallas_codec::minicbor;
use pallas_codec::utils::{Bytes, NonEmptySet};
use pallas_primitives::conway::{Constr, PlutusData, Tx, VKeyWitness};
use pallas_primitives::{BoundedBytes, MaybeIndefArray};
use pallas_traverse::ComputeHash;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::always_ok::{ALWAYS_OK_PLUTUS_CBOR_HEX, UNIT_REDEEMER_HEX};
use crate::cardano::wallet::pub_key_hash_hex;
use crate::epoch::state::{EpochError, EpochResult};

/// A wallet UTxO fetched from Blockfrost, suitable for coin selection.
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub lovelace: u64,
}

/// Encode the treasury oracle datum: `Constr(0, [BoundedBytes(btc_tx)])`.
/// Constructor 0 = unconfirmed TM tx (Binocular sets constructor 1 on
/// Bitcoin confirmation).
fn encode_datum_hex(btc_tx: &[u8]) -> String {
    let datum = PlutusData::Constr(Constr {
        tag: 121, // constructor 0
        any_constructor: None,
        fields: MaybeIndefArray::Def(vec![PlutusData::BoundedBytes(BoundedBytes::from(
            btc_tx.to_vec(),
        ))]),
    });
    let cbor = minicbor::to_vec(&datum).expect("datum CBOR encode");
    hex::encode(cbor)
}

/// Build the Cardano transaction that updates the treasury oracle by
/// creating a new UTxO at the treasury address with:
/// - inline datum: `Constr(0, [BoundedBytes(signed_btc_tx)])`
/// - 1 freshly-minted treasury marker token
///
/// The old oracle UTxO is NOT spent.
///
/// Returns the signed tx hex ready for submission via Blockfrost.
pub fn build_oracle_update_tx(
    treasury_address: &str,
    wallet_address: &str,
    treasury_policy_id: &str,
    treasury_asset_name_hex: &str,
    signed_btc_tx: &[u8],
    wallet_utxos: &[WalletUtxo],
    key: &PrivateKey,
) -> EpochResult<String> {
    let pkh = pub_key_hash_hex(key);
    let datum_hex = encode_datum_hex(signed_btc_tx);
    let asset_unit = format!("{treasury_policy_id}{treasury_asset_name_hex}");

    // Pick the richest wallet UTxO as the fee-paying input.
    let fee_utxo = wallet_utxos
        .iter()
        .max_by_key(|u| u.lovelace)
        .ok_or_else(|| EpochError::Chain("no wallet UTxOs for fee payment".into()))?;

    // Collateral: required for Plutus minting. Use any UTxO with >= 5 ADA
    // (can be the same as the fee input).
    let coll_utxo = wallet_utxos
        .iter()
        .find(|u| u.lovelace >= 5_000_000)
        .ok_or_else(|| {
            EpochError::Chain("no wallet UTxO with >= 5 ADA for collateral".into())
        })?;

    // Min-UTxO for the oracle output with inline datum + token (~2 ADA).
    let oracle_lovelace = 2_000_000u64;

    let body = TxBuilderBody {
        inputs: vec![TxIn::PubKeyTxIn(PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: fee_utxo.tx_hash.clone(),
                tx_index: fee_utxo.output_index,
                amount: Some(vec![Asset::new_from_str(
                    "lovelace",
                    &fee_utxo.lovelace.to_string(),
                )]),
                address: Some(wallet_address.to_string()),
            },
        })],
        outputs: vec![Output {
            address: treasury_address.to_string(),
            amount: vec![
                Asset::new_from_str("lovelace", &oracle_lovelace.to_string()),
                Asset::new_from_str(&asset_unit, "1"),
            ],
            datum: Some(Datum::Inline(datum_hex)),
            reference_script: None,
        }],
        collaterals: vec![PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: coll_utxo.tx_hash.clone(),
                tx_index: coll_utxo.output_index,
                amount: Some(vec![Asset::new_from_str(
                    "lovelace",
                    &coll_utxo.lovelace.to_string(),
                )]),
                address: Some(wallet_address.to_string()),
            },
        }],
        required_signatures: vec![pkh],
        change_address: wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky::Network::Preprod),
        reference_inputs: vec![],
        withdrawals: vec![],
        mints: vec![MintItem::ScriptMint(ScriptMint {
            mint: MintParameter {
                policy_id: treasury_policy_id.to_string(),
                asset_name: treasury_asset_name_hex.to_string(),
                amount: 1,
            },
            redeemer: Some(Redeemer {
                data: UNIT_REDEEMER_HEX.to_string(),
                ex_units: Budget {
                    mem: 14_000,
                    steps: 10_000_000,
                },
            }),
            script_source: Some(ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
                script_cbor: ALWAYS_OK_PLUTUS_CBOR_HEX.to_string(),
                language_version: LanguageVersion::V3,
            })),
        })],
        certificates: vec![],
        votes: vec![],
        fee: None,
        change_datum: None,
        metadata: vec![],
        validity_range: ValidityRange {
            invalid_before: None,
            invalid_hereafter: None,
        },
        total_collateral: None,
        collateral_return_address: None,
    };

    let mut pallas = WhiskyPallas::new(None);
    pallas.tx_builder_body = body;
    let unsigned_hex = pallas
        .serialize_tx_body()
        .map_err(|e| EpochError::Chain(format!("whisky tx build: {e:?}")))?;

    let unsigned_bytes = hex::decode(&unsigned_hex)
        .map_err(|e| EpochError::Chain(format!("unsigned tx hex decode: {e}")))?;
    let mut tx: Tx = minicbor::decode(&unsigned_bytes)
        .map_err(|e| EpochError::Chain(format!("tx minicbor decode: {e}")))?;

    let body_hash = tx.transaction_body.compute_hash();
    let signature = key.sign(body_hash);

    let pk_bytes: [u8; 32] = key.public_key().into();
    let vkey_witness = VKeyWitness {
        vkey: Bytes::from(pk_bytes.to_vec()),
        signature: Bytes::from(signature.as_ref().to_vec()),
    };

    let mut vkeys: Vec<VKeyWitness> = tx
        .transaction_witness_set
        .vkeywitness
        .take()
        .map(|set| set.to_vec())
        .unwrap_or_default();
    vkeys.push(vkey_witness);
    tx.transaction_witness_set.vkeywitness = NonEmptySet::from_vec(vkeys);

    let signed = minicbor::to_vec(&tx)
        .map_err(|e| EpochError::Chain(format!("signed tx encode: {e}")))?;
    Ok(hex::encode(signed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_datum_is_constr_0() {
        let btc_tx = vec![0x02, 0x00, 0x00, 0x00];
        let hex_str = encode_datum_hex(&btc_tx);
        let cbor = hex::decode(&hex_str).unwrap();
        let decoded: PlutusData =
            pallas_codec::minicbor::decode(&cbor).expect("decode");
        match decoded {
            PlutusData::Constr(c) => {
                assert_eq!(c.tag, 121, "should be constructor 0 (unconfirmed)");
                assert_eq!(c.fields.len(), 1);
                match &c.fields[0] {
                    PlutusData::BoundedBytes(b) => {
                        let v: Vec<u8> = b.clone().into();
                        assert_eq!(v, btc_tx);
                    }
                    _ => panic!("expected BoundedBytes"),
                }
            }
            _ => panic!("expected Constr"),
        }
    }
}
