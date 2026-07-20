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
//! carries 1 freshly-minted TM NFT: under the real
//! TreasuryMovementValidator policy the mint is permissionless but
//! gated by chain linkage — the redeemer names the Config UTxO
//! (Genesis) or the predecessor Confirmed record (Chain) as a
//! reference input and the validator checks the embedded BTC tx
//! spends that treasury outpoint. The always-ok scaffold policy
//! (`ALWAYS_OK_PLUTUS_CBOR_HEX`) remains the no-script fallback.
//!
//! The old oracle UTxO is NOT spent — old confirmed UTxOs are needed
//! for minting fBTC proofs. The current treasury is resolved by
//! walking the Confirmed TM chain (see `cardano::tm_chain`).

use pallas_codec::minicbor;
use pallas_codec::utils::{Bytes, NonEmptySet};
use pallas_primitives::conway::{Tx, VKeyWitness};
use pallas_traverse::ComputeHash;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::always_ok::{ALWAYS_OK_PLUTUS_CBOR_HEX, UNIT_REDEEMER_HEX};
use crate::cardano::tx_common::whisky_network;
use crate::cardano::wallet::pub_key_hash_hex;
use crate::epoch::state::{EpochError, EpochResult};

/// A wallet UTxO fetched from Blockfrost, suitable for coin selection.
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub lovelace: u64,
    /// True when the UTxO holds only ADA (no native tokens) AND carries no
    /// reference script. Collateral inputs must be pure-ADA (a token-bearing
    /// pick triggers `CollateralContainsNonADA`), and coin selection must skip
    /// ref-script UTxOs entirely: spending one incurs the Conway per-byte
    /// ref-script fee that generic fee estimation doesn't account for
    /// (`FeeTooSmallUTxO`), and consumes a deployed reference script.
    pub pure_ada: bool,
}

impl WalletUtxo {
    /// Map a raw Blockfrost UTxO to a coin-selection entry. Deliberately
    /// lenient on the quantity parse (`unwrap_or(0)`): a zeroed UTxO is simply
    /// never selected, and an unbalanced tx is rejected by the node anyway.
    #[must_use]
    pub fn from_bf(u: &crate::cardano::bf_http::BfUtxo) -> Self {
        let lovelace: u64 = u
            .amount
            .iter()
            .find(|a| a.unit == "lovelace")
            .map(|a| a.quantity.parse().unwrap_or(0))
            .unwrap_or(0);
        let pure_ada =
            u.amount.iter().all(|a| a.unit == "lovelace") && u.reference_script_hash.is_none();
        WalletUtxo {
            tx_hash: u.tx_hash.clone(),
            output_index: u.output_index,
            lovelace,
            pure_ada,
        }
    }
}

/// Encode the treasury oracle datum: `Constr(constructor, [BoundedBytes(btc_tx)])`.
///
/// Constructor 0 = unconfirmed TM tx; 1 = confirmed (set by Binocular after a
/// Bitcoin proof). Canonical encoding via `cardano::plutus::constr` (see that
/// module for the tag / canonical-encoding rules).
fn encode_datum_hex(btc_tx: &[u8], constructor: u8) -> String {
    let datum = crate::cardano::plutus::constr(
        u64::from(constructor),
        vec![crate::cardano::plutus::bytes(btc_tx)],
    );
    let cbor = minicbor::to_vec(&datum).expect("datum CBOR encode");
    hex::encode(cbor)
}

/// Build the Cardano transaction that updates the treasury oracle by
/// creating a new UTxO at the treasury address with:
/// - inline datum: `Constr(constructor, [BoundedBytes(signed_btc_tx)])`
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
    constructor: u8,
    wallet_utxos: &[WalletUtxo],
    key: &PrivateKey,
    // When `Some`, mint the TM NFT under the real TreasuryMovementValidator policy (CBOR from
    // `binocular tm-script`). `treasury_policy_id` must then be the validator's script hash
    // and `treasury_asset_name_hex` empty (the validator counts the empty-name token). When `None`,
    // falls back to the always-ok scaffold policy (legacy).
    tm_script_cbor: Option<&str>,
    // The chain-linkage mint reference `(tx_hash, index, is_genesis)`: the Config UTxO
    // (Genesis redeemer, before the first TM confirms) or the tip Confirmed TM record
    // (Chain redeemer). Required alongside `tm_script_cbor`. The tx has exactly ONE
    // reference input, so the Chain redeemer's reference-input index is always 0.
    mint_ref: Option<(&str, u32, bool)>,
    // When `Some`, the network's live Plutus cost models `[V1, V2, V3]` (from Blockfrost). Used via
    // `Network::Custom` so the script-integrity hash matches the ledger's even when whisky's
    // hardcoded per-network cost models are stale. `None` → whisky's built-in Preprod models.
    cost_models: Option<Vec<Vec<i64>>>,
) -> EpochResult<String> {
    let pkh = pub_key_hash_hex(key);
    let datum_hex = encode_datum_hex(signed_btc_tx, constructor);
    let asset_unit = format!("{treasury_policy_id}{treasury_asset_name_hex}");

    // Pick the richest wallet UTxO as the fee-paying input.
    let fee_utxo = wallet_utxos
        .iter()
        .max_by_key(|u| u.lovelace)
        .ok_or_else(|| EpochError::Chain("no wallet UTxOs for fee payment".into()))?;

    // Collateral: required for Plutus minting. Must be PURE ADA (a token-bearing UTxO triggers
    // CollateralContainsNonADA) with >= 5 ADA. Can be the same as the fee input.
    let coll_utxo = wallet_utxos
        .iter()
        .find(|u| u.lovelace >= 5_000_000 && u.pure_ada)
        .ok_or_else(|| {
            EpochError::Chain("no pure-ADA wallet UTxO with >= 5 ADA for collateral".into())
        })?;

    // Min-UTxO scales with output size — the inline datum carries the whole signed BTC tx, so a
    // flat 2 ADA is too small (BabbageOutputTooSmallUTxO). Approximate Conway min-UTxO
    // (coinsPerUTxOByte = 4310) generously from the datum size, with a 2-ADA floor.
    let datum_bytes = (datum_hex.len() / 2) as u64;
    let oracle_lovelace = std::cmp::max(2_000_000u64, (datum_bytes + 600) * 4310);

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
        network: Some(whisky_network(&cost_models)),
        // Reference the chain-linkage anchor so the validator's mint branch can verify the
        // embedded BTC tx spends the current treasury outpoint: the Config UTxO (Genesis)
        // or the predecessor Confirmed TM record (Chain).
        reference_inputs: mint_ref
            .map(|(h, i, _)| {
                vec![RefTxIn {
                    tx_hash: h.to_string(),
                    tx_index: i,
                    script_size: None,
                }]
            })
            .unwrap_or_default(),
        withdrawals: vec![],
        mints: vec![MintItem::ScriptMint(ScriptMint {
            mint: MintParameter {
                policy_id: treasury_policy_id.to_string(),
                asset_name: treasury_asset_name_hex.to_string(),
                amount: 1,
            },
            redeemer: Some(Redeemer {
                // Real validator: TmMintRedeemer — Genesis = Constr(0, []), Chain(refInputIdx)
                // = Constr(1, [0]) (single reference input → sorted index 0). Scaffold: unit.
                data: match (tm_script_cbor, mint_ref) {
                    (Some(_), Some((_, _, true))) => hex::encode(
                        minicbor::to_vec(&crate::cardano::plutus::constr(0, vec![]))
                            .expect("redeemer CBOR encode"),
                    ),
                    (Some(_), Some((_, _, false))) => hex::encode(
                        minicbor::to_vec(&crate::cardano::plutus::constr(
                            1,
                            vec![crate::cardano::plutus::int(0)],
                        ))
                        .expect("redeemer CBOR encode"),
                    ),
                    _ => UNIT_REDEEMER_HEX.to_string(),
                },
                // Generous budget for the real TreasuryMovementValidator mint branch (parses the
                // embedded BTC tx's first input, reads the reference datum, checks the NFT
                // binding). The always-ok scaffold needed ~14k mem; the validator needs much
                // more. Well within Conway tx limits.
                ex_units: Budget {
                    mem: 2_000_000,
                    steps: 900_000_000,
                },
            }),
            script_source: Some(ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
                script_cbor: tm_script_cbor
                    .unwrap_or(ALWAYS_OK_PLUTUS_CBOR_HEX)
                    .to_string(),
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

    let signed =
        minicbor::to_vec(&tx).map_err(|e| EpochError::Chain(format!("signed tx encode: {e}")))?;
    Ok(hex::encode(signed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_primitives::conway::PlutusData;

    #[test]
    fn encode_datum_is_constr_0() {
        let btc_tx = vec![0x02, 0x00, 0x00, 0x00];
        let hex_str = encode_datum_hex(&btc_tx, 0);
        let cbor = hex::decode(&hex_str).unwrap();
        let decoded: PlutusData = pallas_codec::minicbor::decode(&cbor).expect("decode");
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
