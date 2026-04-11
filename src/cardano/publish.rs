//! Build and submit Cardano transactions that update the treasury
//! oracle datum.
//!
//! After the FROST signing round produces a witnessed Bitcoin TM
//! transaction, the leader publishes it back to the Cardano treasury
//! oracle UTxO. This means spending the current oracle UTxO (which
//! carries the TMTx marker token) and creating a new one at the same
//! script address with the updated datum:
//!
//! ```text
//! Constr(0, [BoundedBytes(signed_btc_tx)])
//! ```
//!
//! Uses `whisky-pallas` for transaction building with automatic fee
//! estimation and change output. Signing is **not** delegated to
//! whisky (whose `complete_signing` hardcodes 32-byte keys), but done
//! directly with the mnemonic-derived extended ed25519 key via
//! pallas-wallet's `PrivateKey::sign`.

use pallas_codec::minicbor;
use pallas_codec::utils::{Bytes, NonEmptySet};
use pallas_primitives::conway::{Constr, PlutusData, Tx, VKeyWitness};
use pallas_primitives::{BoundedBytes, MaybeIndefArray};
use pallas_traverse::ComputeHash;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::wallet::{pub_key_hash_hex, wallet_address};
use crate::epoch::state::{EpochError, EpochResult};

/// Cached details of the current oracle UTxO, used by the publisher.
#[derive(Debug, Clone)]
pub struct OracleUtxoInfo {
    pub tx_hash: [u8; 32],
    pub tx_index: u64,
    pub lovelace: u64,
}

/// A wallet UTxO fetched from Blockfrost, suitable for coin selection.
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub lovelace: u64,
}

/// Encode the new treasury datum: `Constr(0, [BoundedBytes(btc_tx)])`.
fn encode_datum_hex(signed_btc_tx: &[u8]) -> String {
    let datum = PlutusData::Constr(Constr {
        tag: 121,
        any_constructor: None,
        fields: MaybeIndefArray::Def(vec![PlutusData::BoundedBytes(BoundedBytes::from(
            signed_btc_tx.to_vec(),
        ))]),
    });
    let cbor = minicbor::to_vec(&datum).expect("datum CBOR encode");
    hex::encode(cbor)
}

/// Encode the dummy redeemer: `Constr(0, [])`.
fn encode_redeemer_hex() -> String {
    let redeemer = PlutusData::Constr(Constr {
        tag: 121,
        any_constructor: None,
        fields: MaybeIndefArray::Def(vec![]),
    });
    let cbor = minicbor::to_vec(&redeemer).expect("redeemer CBOR encode");
    hex::encode(cbor)
}

/// Build the Cardano transaction that updates the treasury oracle.
///
/// Uses whisky-pallas to balance the transaction (fee estimation,
/// change output), then signs the body hash ourselves using the
/// mnemonic-derived extended ed25519 key and attaches the
/// `VKeyWitness` to the witness set.
///
/// Returns the signed tx hex ready for submission via Blockfrost.
pub fn build_oracle_update_tx(
    oracle: &OracleUtxoInfo,
    script_address: &str,
    policy_id_hex: &str,
    asset_name_hex: &str,
    script_cbor_hex: &str,
    signed_btc_tx: &[u8],
    wallet_utxos: &[WalletUtxo],
    key: &PrivateKey,
) -> EpochResult<String> {
    let wallet_addr = wallet_address(key);
    let pkh = pub_key_hash_hex(key);

    let oracle_tx_hash = hex::encode(oracle.tx_hash);
    let asset_unit = format!("{policy_id_hex}{asset_name_hex}");
    let datum_hex = encode_datum_hex(signed_btc_tx);
    let redeemer_hex = encode_redeemer_hex();

    // Pick the richest wallet UTxO as the fee-paying input.
    let fee_utxo = wallet_utxos
        .iter()
        .max_by_key(|u| u.lovelace)
        .ok_or_else(|| EpochError::Chain("no wallet UTxOs for fee payment".into()))?;

    // Pick a wallet UTxO with >= 5 ADA as collateral. Can be the same
    // as the fee input.
    let coll_utxo = wallet_utxos
        .iter()
        .find(|u| u.lovelace >= 5_000_000)
        .ok_or_else(|| {
            EpochError::Chain("no wallet UTxO with >= 5 ADA for collateral".into())
        })?;

    // Build the TxBuilderBody. `signing_key` is left empty — we sign
    // ourselves below because whisky's signer only supports 32-byte
    // keys, and our HD-derived key is extended (64 bytes).
    let body = TxBuilderBody {
        inputs: vec![
            // Script input: the oracle UTxO.
            TxIn::ScriptTxIn(ScriptTxIn {
                tx_in: TxInParameter {
                    tx_hash: oracle_tx_hash,
                    tx_index: oracle.tx_index as u32,
                    amount: Some(vec![
                        Asset::new_from_str("lovelace", &oracle.lovelace.to_string()),
                        Asset::new_from_str(&asset_unit, "1"),
                    ]),
                    address: Some(script_address.to_string()),
                },
                script_tx_in: ScriptTxInParameter {
                    script_source: Some(ScriptSource::ProvidedScriptSource(
                        ProvidedScriptSource {
                            script_cbor: script_cbor_hex.to_string(),
                            language_version: LanguageVersion::V3,
                        },
                    )),
                    datum_source: Some(DatumSource::InlineDatumSource(InlineDatumSource {
                        tx_hash: hex::encode(oracle.tx_hash),
                        tx_index: oracle.tx_index as u32,
                    })),
                    redeemer: Some(Redeemer {
                        data: redeemer_hex,
                        ex_units: Budget {
                            mem: 200_000,
                            steps: 200_000_000,
                        },
                    }),
                },
            }),
            // Wallet input: pays the fee.
            TxIn::PubKeyTxIn(PubKeyTxIn {
                tx_in: TxInParameter {
                    tx_hash: fee_utxo.tx_hash.clone(),
                    tx_index: fee_utxo.output_index,
                    amount: Some(vec![Asset::new_from_str(
                        "lovelace",
                        &fee_utxo.lovelace.to_string(),
                    )]),
                    address: Some(wallet_addr.clone()),
                },
            }),
        ],
        outputs: vec![
            // Oracle output: same address, same lovelace + token, updated datum.
            Output {
                address: script_address.to_string(),
                amount: vec![
                    Asset::new_from_str("lovelace", &oracle.lovelace.to_string()),
                    Asset::new_from_str(&asset_unit, "1"),
                ],
                datum: Some(Datum::Inline(datum_hex)),
                reference_script: None,
            },
        ],
        collaterals: vec![PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: coll_utxo.tx_hash.clone(),
                tx_index: coll_utxo.output_index,
                amount: Some(vec![Asset::new_from_str(
                    "lovelace",
                    &coll_utxo.lovelace.to_string(),
                )]),
                address: Some(wallet_addr.clone()),
            },
        }],
        required_signatures: vec![pkh],
        change_address: wallet_addr,
        // Empty — we sign ourselves below.
        signing_key: vec![],
        network: Some(whisky::Network::Preprod),
        reference_inputs: vec![],
        withdrawals: vec![],
        mints: vec![],
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

    // Balance + serialize (unsigned — `signing_key` is empty so
    // `complete_signing` is a no-op; we call `serialize_tx_body`
    // directly and skip it).
    let mut pallas = WhiskyPallas::new(None);
    pallas.tx_builder_body = body;
    let unsigned_hex = pallas
        .serialize_tx_body()
        .map_err(|e| EpochError::Chain(format!("whisky tx build: {e:?}")))?;

    // Decode the balanced unsigned tx, hash the body, sign, attach the
    // VKeyWitness, re-encode.
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

    // Append to any existing vkey witnesses (whisky's balancer shouldn't
    // create any since we passed empty signing_key, but be defensive).
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
    fn encode_datum_roundtrip() {
        let btc_tx = vec![0x02, 0x00, 0x00, 0x00]; // minimal fake
        let hex_str = encode_datum_hex(&btc_tx);
        let cbor = hex::decode(&hex_str).unwrap();
        let decoded: PlutusData =
            pallas_codec::minicbor::decode(&cbor).expect("decode");
        match decoded {
            PlutusData::Constr(c) => {
                assert_eq!(c.tag, 121);
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

    #[test]
    fn encode_redeemer_is_constr_0() {
        let hex_str = encode_redeemer_hex();
        let cbor = hex::decode(&hex_str).unwrap();
        let decoded: PlutusData =
            pallas_codec::minicbor::decode(&cbor).expect("decode");
        match decoded {
            PlutusData::Constr(c) => {
                assert_eq!(c.tag, 121);
                assert_eq!(c.fields.len(), 0);
            }
            _ => panic!("expected Constr(0, [])"),
        }
    }
}
