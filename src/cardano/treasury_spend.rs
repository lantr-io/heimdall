//! R1c: spend the live `treasury_info` state UTxO.
//!
//! `treasury.ak`'s spend branch never stands alone — it demands, in the SAME
//! transaction:
//!
//! 1. a registry-policy mint with non-zero quantity (the register_spo
//!    membership-token mint, or a deregistration burn),
//! 2. a continuing output at the SAME address with the SAME value (the
//!    treasury NFT + its locked ADA travel forever),
//! 3. the continuing inline datum equal to `TreasuryDatum{redeemer.new_*}`.
//!
//! So this module does not build a transaction; it provides the composable
//! *treasury leg* for one: locate the state UTxO among the script address's
//! UTxOs ([`find_treasury_state`]), decode its datum, and produce the whisky
//! `ScriptTxIn` + continuing `Output` pair ([`treasury_spend_leg`]) that the
//! register_spo builder (WI-005) — and later K2 / Update-Y — drop into their
//! `TxBuilderBody` alongside the registry mint.
//!
//! The new datum is caller-supplied: for register_spo it comes from
//! [`crate::cardano::treasury_info::apply_registration`] (only the MPF root
//! changes); K2 rekeying replaces address/outpoint/frost-key too. The on-chain
//! enforcement of *which* transitions are legal lives in the registry policy,
//! not here.

use pallas_codec::minicbor;
use pallas_primitives::PlutusData;
use whisky::*;

use crate::cardano::bf_http::BfUtxo;
use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::treasury_info::{
    TreasuryInfoDatum, TreasuryInfoError, treasury_spend_redeemer,
};

#[derive(Debug)]
pub enum TreasurySpendError {
    /// No UTxO at the script address carries the treasury NFT (policy + name).
    StateNotFound,
    /// More than one UTxO carries the treasury NFT — a supply anomaly (or the
    /// wrong policy/name was queried).
    MultipleStates(usize),
    /// The state UTxO carries assets under a foreign policy; the continuing
    /// output could not reproduce the value faithfully from our model.
    ForeignAssets(String),
    /// The state UTxO has no inline datum (`treasury.ak` requires one).
    NoInlineDatum,
    BadDatumHex(String),
    BadDatumCbor(String),
    BadDatum(TreasuryInfoError),
    BadLovelace(String),
}

impl std::fmt::Display for TreasurySpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateNotFound => write!(f, "no treasury_info state UTxO at the script address"),
            Self::MultipleStates(n) => {
                write!(f, "{n} UTxOs carry the treasury NFT, expected exactly 1")
            }
            Self::ForeignAssets(unit) => {
                write!(f, "state UTxO carries a foreign asset: {unit}")
            }
            Self::NoInlineDatum => write!(f, "state UTxO has no inline datum"),
            Self::BadDatumHex(e) => write!(f, "state datum hex: {e}"),
            Self::BadDatumCbor(e) => write!(f, "state datum CBOR: {e}"),
            Self::BadDatum(e) => write!(f, "state datum: {e}"),
            Self::BadLovelace(e) => write!(f, "state UTxO lovelace: {e}"),
        }
    }
}

impl std::error::Error for TreasurySpendError {}

/// The located on-chain `treasury_info` state UTxO, decoded.
#[derive(Debug, Clone)]
pub struct TreasuryStateUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub lovelace: u64,
    /// Asset name of the treasury NFT (`sha2_256(serialise_data(bootstrap
    /// input_ref))`, fixed at K1).
    pub asset_name_hex: String,
    pub datum: TreasuryInfoDatum,
}

/// Locate the treasury_info state UTxO among `utxos` (fetched from the script
/// address): the UTxO carrying exactly the treasury NFT `policy_id_hex` +
/// `asset_name_hex` (quantity 1) with an inline `TreasuryDatum`.
///
/// The NFT asset name (`sha2_256(serialise_data(bootstrap input_ref))`) is
/// fixed at K1 and recorded by the operator, so we select by the EXACT unit —
/// not merely "any asset under the policy". This matters because `treasury.ak`'s
/// mint branch is permissionless and repeatable: anyone can mint a second
/// treasury-policy NFT (under a different asset name) to the same address. A
/// policy-only filter would then see two candidates and brick discovery, even
/// though the genuine state is still uniquely identified by its name. Matching
/// the exact unit also pins the value-preservation invariant (a foreign or
/// extra asset on the UTxO is rejected rather than silently dropped from the
/// continuing output).
pub fn find_treasury_state(
    utxos: &[BfUtxo],
    policy_id_hex: &str,
    asset_name_hex: &str,
) -> Result<TreasuryStateUtxo, TreasurySpendError> {
    let nft_unit = format!("{policy_id_hex}{asset_name_hex}");
    let candidates: Vec<&BfUtxo> = utxos
        .iter()
        .filter(|u| u.amount.iter().any(|a| a.unit == nft_unit))
        .collect();
    let state = match candidates.as_slice() {
        [] => return Err(TreasurySpendError::StateNotFound),
        [one] => one,
        // A single-mint NFT lives in exactly one UTxO; two matches means a
        // supply anomaly (or the wrong policy/name) — refuse rather than guess.
        many => return Err(TreasurySpendError::MultipleStates(many.len())),
    };

    let mut lovelace = 0u64;
    for a in &state.amount {
        if a.unit == "lovelace" {
            lovelace = a
                .quantity
                .parse()
                .map_err(|e| TreasurySpendError::BadLovelace(format!("{e}")))?;
        } else if a.unit == nft_unit {
            // The treasury NFT — exactly 1 by the policy's mint rule. Anything
            // else means a corrupted instance whose value we can't preserve.
            if a.quantity != "1" {
                return Err(TreasurySpendError::ForeignAssets(format!(
                    "{nft_unit} quantity {}",
                    a.quantity
                )));
            }
        } else {
            // Foreign asset: the value-preservation contract would silently
            // drop it from the continuing output we build.
            return Err(TreasurySpendError::ForeignAssets(a.unit.clone()));
        }
    }

    let datum_hex = state
        .inline_datum
        .as_deref()
        .ok_or(TreasurySpendError::NoInlineDatum)?;
    let datum_cbor =
        hex::decode(datum_hex).map_err(|e| TreasurySpendError::BadDatumHex(e.to_string()))?;
    let datum_pd: PlutusData = minicbor::decode(&datum_cbor)
        .map_err(|e| TreasurySpendError::BadDatumCbor(e.to_string()))?;
    let datum =
        TreasuryInfoDatum::from_plutus_data(&datum_pd).map_err(TreasurySpendError::BadDatum)?;

    Ok(TreasuryStateUtxo {
        tx_hash: state.tx_hash.clone(),
        output_index: state.output_index,
        lovelace,
        asset_name_hex: asset_name_hex.to_string(),
        datum,
    })
}

/// The whisky pieces of the treasury leg: the script input spending the state
/// UTxO (with `TreasurySpendRedeemer{config_ref_input_index, new_*}`) and the
/// continuing output (same address, same value, `new_datum` inline).
///
/// `config_ref_input_index` is carried in the redeemer because the type
/// declares it; the deployed validator never reads it.
///
/// The composing tx must also mint under the registry policy and account for
/// the treasury input's position when building the registry `Register`
/// redeemer — both are the caller's responsibility.
#[must_use]
pub fn treasury_spend_leg(
    state: &TreasuryStateUtxo,
    treasury_script: &ParameterizedScript,
    new_datum: &TreasuryInfoDatum,
    config_ref_input_index: i64,
    network: pallas_addresses::Network,
) -> (TxIn, Output) {
    let script_address = treasury_script.enterprise_address(network);
    let asset_unit = format!("{}{}", treasury_script.hash_hex(), state.asset_name_hex);
    // Value preservation is checked with full equality on-chain — reproduce
    // the input value exactly.
    let value = vec![
        Asset::new_from_str("lovelace", &state.lovelace.to_string()),
        Asset::new_from_str(&asset_unit, "1"),
    ];

    let redeemer_pd = treasury_spend_redeemer(config_ref_input_index, new_datum);
    let redeemer_hex = hex::encode(minicbor::to_vec(&redeemer_pd).expect("redeemer CBOR encode"));

    let tx_in = TxIn::ScriptTxIn(ScriptTxIn {
        tx_in: TxInParameter {
            tx_hash: state.tx_hash.clone(),
            tx_index: state.output_index,
            amount: Some(value.clone()),
            address: Some(script_address.clone()),
        },
        script_tx_in: ScriptTxInParameter {
            script_source: Some(ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
                script_cbor: treasury_script.cbor_hex(),
                language_version: LanguageVersion::V3,
            })),
            // Inline datum lives at the spent UTxO — no datum witness needed.
            datum_source: Some(DatumSource::InlineDatumSource(InlineDatumSource {
                tx_hash: state.tx_hash.clone(),
                tx_index: state.output_index,
            })),
            redeemer: Some(Redeemer {
                data: redeemer_hex,
                // The spend branch walks inputs/outputs and compares values +
                // datum — light. Budget like the other bifrost legs; the
                // register_spo mint (MPF insert) dominates the tx budget.
                ex_units: Budget {
                    mem: 2_000_000,
                    steps: 900_000_000,
                },
            }),
        },
    });

    let output = Output {
        address: script_address,
        amount: value,
        datum: Some(Datum::Inline(hex::encode(new_datum.to_cbor()))),
        reference_script: None,
    };

    (tx_in, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::bf_http::BfAmount;
    use crate::cardano::blueprint;
    use crate::cardano::mpf;
    use crate::cardano::treasury_info::apply_registration;
    use pallas_primitives::BoundedBytes;

    fn test_script() -> blueprint::ParameterizedScript {
        let code = include_str!("../../tests/fixtures/treasury_info_code.txt");
        blueprint::apply_params(
            code.trim(),
            &[PlutusData::BoundedBytes(BoundedBytes::from(vec![
                0x79u8;
                28
            ]))],
        )
        .unwrap()
    }

    fn sample_datum(root: mpf::Hash) -> TreasuryInfoDatum {
        TreasuryInfoDatum {
            bifrost_identity_root: root,
            current_treasury_address: b"\x51\x20treasury-spk".to_vec(),
            current_treasury_utxo_id: vec![0x11; 36],
            current_spos_frost_key: vec![0xAB; 32],
        }
    }

    // The genuine state UTxO's NFT asset name (would be sha2_256(serialise_data(
    // input_ref)) on-chain; any fixed 32-byte value works for these tests).
    fn nft_name() -> String {
        "ee".repeat(32)
    }

    fn state_utxo(policy_hex: &str, datum: &TreasuryInfoDatum) -> BfUtxo {
        named_state_utxo(policy_hex, &nft_name(), datum)
    }

    fn named_state_utxo(policy_hex: &str, name_hex: &str, datum: &TreasuryInfoDatum) -> BfUtxo {
        BfUtxo {
            tx_hash: "dd".repeat(32),
            output_index: 0,
            amount: vec![
                BfAmount {
                    unit: "lovelace".into(),
                    quantity: "3104330".into(),
                },
                BfAmount {
                    unit: format!("{policy_hex}{name_hex}"),
                    quantity: "1".into(),
                },
            ],
            inline_datum: Some(hex::encode(datum.to_cbor())),
        }
    }

    fn ada_utxo(lovelace: u64) -> BfUtxo {
        BfUtxo {
            tx_hash: "cc".repeat(32),
            output_index: 1,
            amount: vec![BfAmount {
                unit: "lovelace".into(),
                quantity: lovelace.to_string(),
            }],
            inline_datum: None,
        }
    }

    #[test]
    fn finds_the_singleton_state() {
        let script = test_script();
        let datum = sample_datum(mpf::NULL_HASH);
        let utxos = vec![ada_utxo(2_000_000), state_utxo(&script.hash_hex(), &datum)];
        let state = find_treasury_state(&utxos, &script.hash_hex(), &nft_name()).unwrap();
        assert_eq!(state.tx_hash, "dd".repeat(32));
        assert_eq!(state.lovelace, 3_104_330);
        assert_eq!(state.asset_name_hex, nft_name());
        assert_eq!(state.datum, datum);
    }

    // A second, attacker-minted treasury NFT (different asset name, same policy
    // and address — treasury.ak's mint branch is permissionless/repeatable) must
    // NOT brick discovery: selecting by the genuine asset name ignores it.
    #[test]
    fn ignores_a_second_policy_nft_with_a_different_name() {
        let script = test_script();
        let policy = script.hash_hex();
        let datum = sample_datum(mpf::NULL_HASH);
        let genuine = state_utxo(&policy, &datum);
        let mut decoy = named_state_utxo(&policy, &"aa".repeat(32), &datum);
        decoy.tx_hash = "ff".repeat(32);
        let state = find_treasury_state(&[decoy, genuine], &policy, &nft_name()).unwrap();
        assert_eq!(state.tx_hash, "dd".repeat(32));
        assert_eq!(state.asset_name_hex, nft_name());
    }

    #[test]
    fn discovery_rejects_corrupt_sets() {
        let script = test_script();
        let policy = script.hash_hex();
        let datum = sample_datum(mpf::NULL_HASH);

        // none
        assert!(matches!(
            find_treasury_state(&[ada_utxo(1)], &policy, &nft_name()),
            Err(TreasurySpendError::StateNotFound)
        ));
        // two UTxOs carrying the SAME NFT name (supply anomaly)
        let two = vec![state_utxo(&policy, &datum), state_utxo(&policy, &datum)];
        assert!(matches!(
            find_treasury_state(&two, &policy, &nft_name()),
            Err(TreasurySpendError::MultipleStates(2))
        ));
        // missing inline datum
        let mut no_datum = state_utxo(&policy, &datum);
        no_datum.inline_datum = None;
        assert!(matches!(
            find_treasury_state(&[no_datum], &policy, &nft_name()),
            Err(TreasurySpendError::NoInlineDatum)
        ));
        // garbage datum CBOR
        let mut bad = state_utxo(&policy, &datum);
        bad.inline_datum = Some("ff".into());
        assert!(matches!(
            find_treasury_state(&[bad], &policy, &nft_name()),
            Err(TreasurySpendError::BadDatumCbor(_))
        ));
        // foreign asset alongside the NFT
        let mut foreign = state_utxo(&policy, &datum);
        foreign.amount.push(BfAmount {
            unit: format!("{}{}", "ab".repeat(28), "cd".repeat(8)),
            quantity: "5".into(),
        });
        assert!(matches!(
            find_treasury_state(&[foreign], &policy, &nft_name()),
            Err(TreasurySpendError::ForeignAssets(_))
        ));
    }

    // The leg preserves the value/address exactly and carries the new datum +
    // spend redeemer — the three things treasury.ak's spend branch checks.
    #[test]
    fn spend_leg_preserves_value_and_updates_datum() {
        let script = test_script();
        let old = sample_datum(mpf::NULL_HASH);
        let state = find_treasury_state(
            &[state_utxo(&script.hash_hex(), &old)],
            &script.hash_hex(),
            &nft_name(),
        )
        .unwrap();

        let mut new_datum = old.clone();
        new_datum.bifrost_identity_root = [7u8; 32];
        let (tx_in, output) = treasury_spend_leg(
            &state,
            &script,
            &new_datum,
            0,
            pallas_addresses::Network::Testnet,
        );

        let TxIn::ScriptTxIn(stx) = &tx_in else {
            panic!("expected ScriptTxIn");
        };
        // Input is the located state UTxO, output reproduces its value at the
        // same script address.
        assert_eq!(stx.tx_in.tx_hash, state.tx_hash);
        assert_eq!(stx.tx_in.tx_index, state.output_index);
        assert_eq!(stx.tx_in.amount.as_ref().unwrap(), &output.amount);
        assert_eq!(stx.tx_in.address.as_ref().unwrap(), &output.address);
        assert_eq!(
            output.address,
            script.enterprise_address(pallas_addresses::Network::Testnet)
        );

        // Continuing datum is the NEW datum.
        let Some(Datum::Inline(datum_hex)) = &output.datum else {
            panic!("expected inline datum");
        };
        assert_eq!(datum_hex, &hex::encode(new_datum.to_cbor()));

        // Redeemer: Constr 0, [config_ref_input_index, new_root, new_address,
        // new_utxo_id, new_frost_key].
        let r = &stx.script_tx_in.redeemer.as_ref().unwrap().data;
        let pd: PlutusData = minicbor::decode(&hex::decode(r).unwrap()).unwrap();
        let PlutusData::Constr(c) = pd else {
            panic!("expected Constr redeemer");
        };
        assert_eq!(c.tag, 121);
        assert_eq!(c.fields.len(), 5);
        assert!(
            matches!(&c.fields[1], PlutusData::BoundedBytes(b) if **b == new_datum.bifrost_identity_root)
        );
    }

    // The R1c wiring end to end (offline): located state → apply_registration
    // → spend leg; the continuing datum carries exactly the root the registry
    // validator will recompute from the absence proof.
    #[test]
    fn registration_transition_flows_into_the_leg() {
        let script = test_script();
        let trie = mpf::Trie::from_pairs(&[
            (b"spo-a".to_vec(), b"pool-a".to_vec()),
            (b"spo-b".to_vec(), b"pool-b".to_vec()),
        ])
        .unwrap();
        let old = sample_datum(trie.root_hash());
        let state = find_treasury_state(
            &[state_utxo(&script.hash_hex(), &old)],
            &script.hash_hex(),
            &nft_name(),
        )
        .unwrap();

        let (new_datum, proof) =
            apply_registration(&state.datum, &trie, b"new-spo-pk", b"new-pool").unwrap();
        let (_, output) = treasury_spend_leg(
            &state,
            &script,
            &new_datum,
            0,
            pallas_addresses::Network::Testnet,
        );

        let Some(Datum::Inline(datum_hex)) = &output.datum else {
            panic!("expected inline datum");
        };
        let decoded: PlutusData = minicbor::decode(&hex::decode(datum_hex).unwrap()).unwrap();
        let continued = TreasuryInfoDatum::from_plutus_data(&decoded).unwrap();
        // The continued root is the proof-derived insert of the new SPO — the
        // same computation the on-chain registry validator performs.
        assert_eq!(
            continued.bifrost_identity_root,
            mpf::including(b"new-spo-pk", b"new-pool", &proof).unwrap()
        );
        // Everything else is preserved by registration.
        assert_eq!(
            continued.current_treasury_address,
            old.current_treasury_address
        );
        assert_eq!(continued.current_spos_frost_key, old.current_spos_frost_key);
    }

    // Compose the leg into a full whisky tx (with a stand-in mint for the
    // registry policy, which whisky doesn't enforce) and serialize it — proves
    // the leg parts are accepted by the tx builder and survive into the wire
    // format intact. This mirrors the WI-005 composition.
    #[test]
    fn leg_composes_into_a_buildable_tx() {
        use crate::cardano::always_ok::{ALWAYS_OK_PLUTUS_CBOR_HEX, UNIT_REDEEMER_HEX};
        use crate::cardano::wallet::derive_payment_key;
        use pallas_primitives::conway::Tx;

        let script = test_script();
        let old = sample_datum(mpf::NULL_HASH);
        let state = find_treasury_state(
            &[state_utxo(&script.hash_hex(), &old)],
            &script.hash_hex(),
            &nft_name(),
        )
        .unwrap();
        let mut new_datum = old.clone();
        new_datum.bifrost_identity_root = [7u8; 32];
        let (treasury_in, treasury_out) = treasury_spend_leg(
            &state,
            &script,
            &new_datum,
            0,
            pallas_addresses::Network::Testnet,
        );

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_payment_key(mnemonic).unwrap();
        let wallet_addr = crate::cardano::wallet::wallet_address(&key);
        let fee_in = TxIn::PubKeyTxIn(PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: "aa".repeat(32),
                tx_index: 0,
                amount: Some(vec![Asset::new_from_str("lovelace", "50000000")]),
                address: Some(wallet_addr.clone()),
            },
        });
        let collateral = PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: "aa".repeat(32),
                tx_index: 0,
                amount: Some(vec![Asset::new_from_str("lovelace", "50000000")]),
                address: Some(wallet_addr.clone()),
            },
        };
        let always_ok_hash =
            blueprint::script_hash_v3(&hex::decode(ALWAYS_OK_PLUTUS_CBOR_HEX).unwrap());

        let body = TxBuilderBody {
            inputs: vec![fee_in, treasury_in],
            outputs: vec![treasury_out],
            collaterals: vec![collateral],
            required_signatures: vec![crate::cardano::wallet::pub_key_hash_hex(&key)],
            change_address: wallet_addr,
            signing_key: vec![],
            network: Some(whisky::Network::Preprod),
            reference_inputs: vec![],
            withdrawals: vec![],
            mints: vec![MintItem::ScriptMint(ScriptMint {
                mint: MintParameter {
                    policy_id: hex::encode(always_ok_hash),
                    asset_name: "aa".repeat(28),
                    amount: 1,
                },
                redeemer: Some(Redeemer {
                    data: UNIT_REDEEMER_HEX.to_string(),
                    ex_units: Budget {
                        mem: 100_000,
                        steps: 50_000_000,
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

        let mut pallas = whisky_pallas::WhiskyPallas::new(None);
        pallas.tx_builder_body = body;
        let tx_hex = pallas
            .serialize_tx_body()
            .expect("whisky builds the composed tx");
        let tx: Tx = minicbor::decode(&hex::decode(&tx_hex).unwrap()).unwrap();

        // The treasury input is spent and the continuing output survives with
        // value + new datum.
        assert!(
            tx.transaction_body
                .inputs
                .iter()
                .any(|i| i.transaction_id.as_slice() == [0xdd; 32] && i.index == 0)
        );
        let pallas_primitives::conway::PseudoTransactionOutput::PostAlonzo(out) =
            &tx.transaction_body.outputs[0]
        else {
            panic!("expected post-alonzo output");
        };
        let Some(pallas_primitives::conway::DatumOption::Data(wrapped)) = &out.datum_option else {
            panic!("expected inline datum on the continuing output");
        };
        assert_eq!(
            TreasuryInfoDatum::from_plutus_data(&wrapped.0).unwrap(),
            new_datum
        );
        // A Spend redeemer is attached.
        let redeemers = tx.transaction_witness_set.redeemer.as_ref().unwrap();
        let has_spend = match redeemers {
            pallas_primitives::conway::Redeemers::List(rs) => rs
                .iter()
                .any(|r| matches!(r.tag, pallas_primitives::conway::RedeemerTag::Spend)),
            pallas_primitives::conway::Redeemers::Map(kv) => kv
                .iter()
                .any(|(k, _)| matches!(k.tag, pallas_primitives::conway::RedeemerTag::Spend)),
        };
        assert!(has_spend, "spend redeemer attached");
    }
}
