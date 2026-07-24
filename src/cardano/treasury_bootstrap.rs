//! K1 / init: bootstrap the `treasury.ak` (`treasury_info`) state UTxO.
//!
//! A one-shot mint creates the bridge's roster/key oracle. The tx must:
//!
//! 1. spend a wallet UTxO `input_ref` (the one-shot — replays are impossible
//!    because an outpoint spends once),
//! 2. mint exactly 1 treasury NFT under the parameterized `treasury_info`
//!    policy with asset name `sha2_256(serialise_data(input_ref))`,
//! 3. send the NFT to the script's enterprise address with the inline
//!    `TreasuryDatum { bifrost_identity_root: EMPTY-MPF-ROOT,
//!    current_treasury_address, current_treasury_utxo_id,
//!    current_spos_frost_key }`,
//!
//! with the `TreasuryMintRedeemer` repeating `input_ref` + the three datum
//! byte-fields. This sets the *initial* FROST group key (bootstrap
//! PublishKeys); rotation (K2 / Update-Y) has no on-chain path yet.
//!
//! The datum's BTC-side fields are opaque `ByteArray`s to the contract; the
//! heimdall conventions are: `current_treasury_address` = the treasury P2TR
//! scriptPubKey (`0x5120 || x-only key`), `current_treasury_utxo_id` = the
//! Bitcoin consensus serialization of the outpoint (txid little-endian ||
//! u32-LE vout, 36 bytes), `current_spos_frost_key` = 32-byte x-only `y_fed`.
//!
//! `serialise_data` here must be byte-identical to the Plutus builtin: Constr
//! 0..=6 → CBOR tag 121+c, **indefinite-length** field arrays when non-empty
//! (`d8799f…ff`), definite `0x80` when empty — pinned by the aiken stdlib
//! vectors `cbor.serialise(Some(42)) == #"d8799f182aff"`,
//! `cbor.serialise(None) == #"d87a80"`.

use bitcoin::hashes::{Hash as _, sha256};
use pallas_codec::minicbor;
use pallas_codec::utils::{Bytes, NonEmptySet};
use pallas_primitives::PlutusData;
use pallas_primitives::conway::{Tx, VKeyWitness};
use pallas_traverse::ComputeHash;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::mpf;
use crate::cardano::plutus::{bytes, constr, int, int_from_u64};
use crate::cardano::publish::WalletUtxo;
use crate::cardano::treasury_info::TreasuryInfoDatum;
use crate::cardano::tx_common::{network_from_address, whisky_network};
use crate::cardano::wallet::pub_key_hash_hex;
use crate::epoch::state::{EpochError, EpochResult};

// Plutus encode/decode (constructor tags, canonical encoding) live in
// `crate::cardano::plutus`. `hash_output_ref` relies on `constr`'s canonical
// encoding to byte-match the on-chain `serialiseData` of the OutputReference.

// ---------------------------------------------------------------------------
// hash_output_ref — the one-shot NFT asset name
// ---------------------------------------------------------------------------

/// `bifrost/utils.hash_output_ref`: `sha2_256(serialise_data(OutputReference {
/// transaction_id, output_index }))`. The validator recomputes this on-chain
/// from the redeemer's `input_ref`, so the encoding must match the Plutus
/// `serialiseData` builtin exactly (indefinite-length Constr fields).
#[must_use]
pub fn hash_output_ref(tx_id: &[u8; 32], output_index: u64) -> [u8; 32] {
    let output_ref = output_ref_plutus_data(tx_id, output_index);
    let serialised = minicbor::to_vec(&output_ref).expect("PlutusData CBOR encode");
    sha256::Hash::hash(&serialised).to_byte_array()
}

/// The `OutputReference` as Plutus data, canonically encoded — shared by the
/// asset-name hash and the redeemer, so the name the policy recomputes from
/// the redeemer is the name we mint by construction.
#[must_use]
pub fn output_ref_plutus_data(tx_id: &[u8; 32], output_index: u64) -> PlutusData {
    constr(0, vec![bytes(tx_id), int_from_u64(output_index)])
}

// ---------------------------------------------------------------------------
// Bootstrap datum + mint redeemer
// ---------------------------------------------------------------------------

/// The K1 initial datum: empty MPF identity root + the current frost key +
/// the federation fields. In Phase 1 `current_spos_frost_key` == `y_federation`
/// (the federation is the key-path signer until the first DKG).
#[must_use]
pub fn bootstrap_datum(
    current_spos_frost_key: Vec<u8>,
    y_federation: Vec<u8>,
    federation_csv_blocks: i64,
) -> TreasuryInfoDatum {
    TreasuryInfoDatum {
        bifrost_identity_root: mpf::NULL_HASH,
        current_spos_frost_key,
        y_federation,
        federation_csv_blocks,
        // No reset at bootstrap; empty until the first FederationReset consumes a sweep.
        last_reset_tm_txid: vec![],
    }
}

/// `TreasuryMintRedeemer = Constr(0, [input_ref, current_spos_frost_key,
/// y_federation, federation_csv_blocks])`. The fields must equal the datum's —
/// the validator rebuilds the expected datum from the redeemer.
#[must_use]
pub fn treasury_mint_redeemer(
    tx_id: &[u8; 32],
    output_index: u64,
    datum: &TreasuryInfoDatum,
) -> PlutusData {
    constr(
        0,
        vec![
            output_ref_plutus_data(tx_id, output_index),
            bytes(&datum.current_spos_frost_key),
            bytes(&datum.y_federation),
            int(datum.federation_csv_blocks),
        ],
    )
}

// ---------------------------------------------------------------------------
// Tx builder
// ---------------------------------------------------------------------------

/// A built (signed, unsubmitted) K1 bootstrap tx plus everything an operator
/// needs to record about the new state UTxO.
#[derive(Debug, Clone)]
pub struct TreasuryBootstrapTx {
    pub signed_tx_hex: String,
    /// `treasury_info` script hash = the treasury NFT policy id.
    pub policy_id_hex: String,
    /// `sha2_256(serialise_data(input_ref))` — the treasury NFT asset name.
    pub asset_name_hex: String,
    /// Enterprise script address holding the state UTxO.
    pub script_address: String,
    /// The consumed one-shot `(tx_hash, output_index)`.
    pub input_ref: (String, u32),
}

/// Build + sign the K1 bootstrap mint. The richest wallet UTxO doubles as the
/// one-shot `input_ref` and the fee input; a pure-ADA UTxO (possibly the same
/// one) provides collateral. The script output carries only the freshly
/// minted NFT (plus min-ADA) — the validator requires exactly one output at
/// its own payment credential, with exactly that token and the bootstrap
/// datum inline.
pub fn build_treasury_bootstrap_tx(
    treasury_script: &ParameterizedScript,
    wallet_address: &str,
    wallet_utxos: &[WalletUtxo],
    datum: &TreasuryInfoDatum,
    key: &PrivateKey,
    // Live `[V1, V2, V3]` cost models (see `publish::build_oracle_update_tx`);
    // `None` → whisky's built-in Preprod models.
    cost_models: Option<Vec<Vec<i64>>>,
) -> EpochResult<TreasuryBootstrapTx> {
    if datum.bifrost_identity_root != mpf::NULL_HASH {
        return Err(EpochError::Chain(
            "bootstrap datum must carry the empty MPF root (the validator pins \
             mpf.root(mpf.empty))"
                .into(),
        ));
    }

    let pkh = pub_key_hash_hex(key);
    let network = network_from_address(wallet_address);
    let script_address = treasury_script.enterprise_address(network);
    let policy_id_hex = treasury_script.hash_hex();

    // The one-shot + fee input: the richest PURE-ADA wallet UTxO. Pure-ADA is
    // required — this builder emits a single change output that forwards only
    // ADA, so a token-bearing one-shot would silently drop its native tokens
    // and the tx fails ledger value-conservation (ValueNotConservedUTxO, hit on
    // a preprod wallet carrying leftover test tokens). Matches the pure-ADA
    // selection in `tx_common::select_fee` / `register_pool::select_inputs`.
    let fee_utxo = wallet_utxos
        .iter()
        .filter(|u| u.pure_ada)
        .max_by_key(|u| u.lovelace)
        .ok_or_else(|| {
            EpochError::Chain("no pure-ADA wallet UTxO for the one-shot input".into())
        })?;
    let tx_id: [u8; 32] = hex::decode(&fee_utxo.tx_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            EpochError::Chain(format!("bad wallet UTxO tx hash: {}", fee_utxo.tx_hash))
        })?;

    let asset_name = hash_output_ref(&tx_id, u64::from(fee_utxo.output_index));
    let asset_name_hex = hex::encode(asset_name);
    let asset_unit = format!("{policy_id_hex}{asset_name_hex}");

    let redeemer = treasury_mint_redeemer(&tx_id, u64::from(fee_utxo.output_index), datum);
    let redeemer_hex = hex::encode(minicbor::to_vec(&redeemer).expect("redeemer CBOR encode"));
    let datum_hex = hex::encode(datum.to_cbor());

    // Collateral: pure ADA, >= 5 ADA (may be the same UTxO as the fee input).
    let coll_utxo = wallet_utxos
        .iter()
        .find(|u| u.lovelace >= 5_000_000 && u.pure_ada)
        .ok_or_else(|| {
            EpochError::Chain("no pure-ADA wallet UTxO with >= 5 ADA for collateral".into())
        })?;

    // Min-UTxO: the datum is small (~150 bytes) but the locked value persists
    // across every future treasury_info spend (the validator preserves it), so
    // stay with the conservative datum-scaled formula from publish.rs.
    let datum_bytes = (datum_hex.len() / 2) as u64;
    let state_lovelace = std::cmp::max(2_000_000u64, (datum_bytes + 600) * 4310);

    // Single-input coin selection: fail with an actionable message instead of
    // an opaque whisky balancing error when the richest UTxO can't cover the
    // state output plus a fee margin.
    if fee_utxo.lovelace < state_lovelace + 1_000_000 {
        return Err(EpochError::Chain(format!(
            "largest wallet UTxO ({} lovelace) cannot cover the {state_lovelace}-lovelace \
             state output plus fees — fund the wallet or consolidate UTxOs",
            fee_utxo.lovelace
        )));
    }

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
            address: script_address.clone(),
            amount: vec![
                Asset::new_from_str("lovelace", &state_lovelace.to_string()),
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
        reference_inputs: vec![],
        withdrawals: vec![],
        mints: vec![MintItem::ScriptMint(ScriptMint {
            mint: MintParameter {
                policy_id: policy_id_hex.clone(),
                asset_name: asset_name_hex.clone(),
                amount: 1,
            },
            redeemer: Some(Redeemer {
                data: redeemer_hex,
                // The mint branch filters outputs, re-serialises + sha256's the
                // input_ref and compares the datum — light, but budget like
                // publish.rs; well within Conway tx limits.
                ex_units: Budget {
                    mem: 2_000_000,
                    steps: 900_000_000,
                },
            }),
            script_source: Some(ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
                script_cbor: treasury_script.cbor_hex(),
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

    Ok(TreasuryBootstrapTx {
        signed_tx_hex: hex::encode(signed),
        policy_id_hex,
        asset_name_hex,
        script_address,
        input_ref: (fee_utxo.tx_hash.clone(), fee_utxo.output_index),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::blueprint;
    use crate::cardano::wallet::derive_payment_key;
    use pallas_addresses::Address;
    use pallas_primitives::BoundedBytes;
    use pallas_primitives::conway::{DatumOption, PseudoTransactionOutput};

    // sha2_256(d8799f5820 || aa*32 || <index> || ff) — independently computed
    // (python hashlib) from the plutus-core serialiseData encoding pinned by
    // the aiken stdlib vectors quoted in the module doc.
    #[test]
    fn hash_output_ref_matches_serialise_data_vectors() {
        assert_eq!(
            hex::encode(hash_output_ref(&[0xaa; 32], 1)),
            "feb569f652252c9e3afca8a223332807cc01336c0ca4399e064d8af9519125ee"
        );
        assert_eq!(
            hex::encode(hash_output_ref(&[0xaa; 32], 0)),
            "91634ec36a60a9260f398e1b216636636da61d764f3499a2e8b3b7a309302edb"
        );
    }

    // Pin the exact serialise_data bytes (indefinite-length fields), not just
    // the hash, so a pallas encoding change fails loudly here.
    #[test]
    fn output_ref_serialise_data_is_indefinite() {
        let output_ref = output_ref_plutus_data(&[0xaa; 32], 1);
        let cbor = minicbor::to_vec(&output_ref).unwrap();
        assert_eq!(
            hex::encode(cbor),
            format!("d8799f5820{}01ff", "aa".repeat(32))
        );
    }

    // The whole redeemer must also be canonically encoded: the Rust uplc
    // evaluator re-serialises `redeemer.input_ref` with encoding memory, so a
    // definite-encoded redeemer makes the asset-name check fail in simulation
    // (a Haskell node would accept it — but tooling parity matters).
    #[test]
    fn mint_redeemer_is_canonical() {
        let d = bootstrap_datum(vec![1, 2], vec![3, 4], 6);
        let r = treasury_mint_redeemer(&[0xaa; 32], 1, &d);
        let hex = hex::encode(minicbor::to_vec(&r).unwrap());
        // Constr 0 indef [ Constr 0 indef [ bytes32, 1 ], 0102, 0304, int 6 ]
        assert_eq!(
            hex,
            format!("d8799fd8799f5820{}01ff42010242030406ff", "aa".repeat(32))
        );
    }

    #[test]
    fn bootstrap_datum_has_empty_root_and_roundtrips() {
        let d = bootstrap_datum(vec![0xAB; 32], vec![0xCD; 32], 144);
        assert_eq!(d.bifrost_identity_root, mpf::NULL_HASH);
        let decoded: PlutusData = minicbor::decode(&d.to_cbor()).unwrap();
        assert_eq!(TreasuryInfoDatum::from_plutus_data(&decoded).unwrap(), d);
    }

    #[test]
    fn mint_redeemer_shape() {
        let d = bootstrap_datum(vec![1, 2], vec![3, 4], 6);
        let r = treasury_mint_redeemer(&[0xaa; 32], 1, &d);
        let cbor = minicbor::to_vec(&r).unwrap();
        let back: PlutusData = minicbor::decode(&cbor).unwrap();
        let PlutusData::Constr(c) = back else {
            panic!("expected Constr");
        };
        assert_eq!(c.tag, 121);
        assert_eq!(c.fields.len(), 4);
        let PlutusData::Constr(input_ref) = &c.fields[0] else {
            panic!("expected input_ref Constr");
        };
        assert_eq!(input_ref.tag, 121);
        assert_eq!(input_ref.fields.len(), 2);
        assert!(matches!(&c.fields[1], PlutusData::BoundedBytes(b) if **b == [1u8, 2]));
    }

    // The builder refuses a datum whose root is not the empty-MPF root — the
    // validator pins mpf.root(mpf.empty), so anything else burns fees on a
    // guaranteed phase-2 failure.
    #[test]
    fn build_rejects_non_empty_root() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_payment_key(mnemonic).unwrap();
        let wallet_addr = crate::cardano::wallet::wallet_address(&key);
        let mut datum = bootstrap_datum(vec![1], vec![2], 3);
        datum.bifrost_identity_root = [9u8; 32];
        let utxos = vec![WalletUtxo {
            tx_hash: "aa".repeat(32),
            output_index: 0,
            lovelace: 50_000_000,
            pure_ada: true,
        }];
        let err =
            build_treasury_bootstrap_tx(&test_script(), &wallet_addr, &utxos, &datum, &key, None)
                .unwrap_err();
        assert!(err.to_string().contains("empty MPF root"), "{err}");
    }

    fn test_script() -> blueprint::ParameterizedScript {
        let code = include_str!("../../tests/fixtures/treasury_info_code.txt");
        let registry_policy = [0x79u8; 28];
        blueprint::apply_params(
            code.trim(),
            &[PlutusData::BoundedBytes(BoundedBytes::from(
                registry_policy.to_vec(),
            ))],
        )
        .unwrap()
    }

    // Build the whole signed tx against fake wallet UTxOs and check every
    // on-chain-relevant property: the one-shot is spent, exactly one output at
    // the script address carrying (only) the NFT named by hash_output_ref, the
    // bootstrap datum inline, and a vkey witness present.
    #[test]
    fn build_bootstrap_tx_end_to_end() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_payment_key(mnemonic).unwrap();
        let wallet_addr = crate::cardano::wallet::wallet_address(&key);
        let script = test_script();

        let one_shot_hash = "bb".repeat(32);
        let utxos = vec![
            WalletUtxo {
                tx_hash: "cc".repeat(32),
                output_index: 0,
                lovelace: 8_000_000,
                pure_ada: true,
            },
            WalletUtxo {
                tx_hash: one_shot_hash.clone(),
                output_index: 3,
                lovelace: 50_000_000,
                pure_ada: true,
            },
        ];
        let datum = bootstrap_datum(vec![0xAB; 32], vec![0xCD; 32], 144);

        let built =
            build_treasury_bootstrap_tx(&script, &wallet_addr, &utxos, &datum, &key, None).unwrap();

        // The richest UTxO became the one-shot, and names the NFT.
        assert_eq!(built.input_ref, (one_shot_hash.clone(), 3));
        let expected_name = hash_output_ref(&[0xbb; 32], 3);
        assert_eq!(built.asset_name_hex, hex::encode(expected_name));
        assert_eq!(built.policy_id_hex, script.hash_hex());

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();

        // One-shot input is spent.
        assert!(
            tx.transaction_body
                .inputs
                .iter()
                .any(|i| i.transaction_id.as_slice() == [0xbb; 32] && i.index == 3)
        );

        // Mint: exactly our policy with exactly our asset, quantity 1.
        let mint = tx.transaction_body.mint.as_ref().expect("mint present");
        let policies: Vec<_> = mint.iter().collect();
        assert_eq!(policies.len(), 1);
        let (policy, assets) = &policies[0];
        assert_eq!(policy.as_slice(), script.hash);
        let assets: Vec<_> = assets.iter().collect();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].0.as_slice(), expected_name);
        assert_eq!(i64::from(assets[0].1), 1);

        // Output 0: script address, NFT + ADA only, inline bootstrap datum.
        let PseudoTransactionOutput::PostAlonzo(out) = &tx.transaction_body.outputs[0] else {
            panic!("expected post-alonzo output");
        };
        let script_addr_bytes = Address::from_bech32(&built.script_address)
            .unwrap()
            .to_vec();
        assert_eq!(out.address.as_slice(), script_addr_bytes);
        let Some(DatumOption::Data(wrapped)) = &out.datum_option else {
            panic!("expected inline datum");
        };
        assert_eq!(
            TreasuryInfoDatum::from_plutus_data(&wrapped.0).unwrap(),
            datum
        );

        // The script output's value is lovelace + exactly the one NFT — the
        // validator requires flatten(without_lovelace(value)) == [(policy,
        // name, 1)], so any stray asset is a phase-2 failure.
        let pallas_primitives::conway::Value::Multiasset(_, ma) = &out.value else {
            panic!("expected multiasset value on the state output");
        };
        let out_policies: Vec<_> = ma.iter().collect();
        assert_eq!(out_policies.len(), 1);
        assert_eq!(out_policies[0].0.as_slice(), script.hash);
        let out_assets: Vec<_> = out_policies[0].1.iter().collect();
        assert_eq!(out_assets.len(), 1);
        assert_eq!(out_assets[0].0.as_slice(), expected_name);
        assert_eq!(u64::from(out_assets[0].1), 1);

        // Witness set: the mint redeemer rides along, canonically encoded.
        let redeemers = tx
            .transaction_witness_set
            .redeemer
            .as_ref()
            .expect("redeemer present");
        let expected_redeemer = treasury_mint_redeemer(&[0xbb; 32], 3, &datum);
        let redeemer_matches = match redeemers {
            pallas_primitives::conway::Redeemers::List(rs) => {
                rs.iter().any(|r| r.data == expected_redeemer)
            }
            pallas_primitives::conway::Redeemers::Map(kv) => {
                kv.iter().any(|(_, v)| v.data == expected_redeemer)
            }
        };
        assert!(redeemer_matches, "mint redeemer not found in witness set");

        // Signed: a vkey witness for our key.
        let pk: [u8; 32] = key.public_key().into();
        assert!(
            tx.transaction_witness_set
                .vkeywitness
                .as_ref()
                .unwrap()
                .iter()
                .any(|w| w.vkey.as_slice() == pk)
        );
    }
}
