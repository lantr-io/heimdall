//! Build and submit Cardano transactions that update the treasury
//! oracle datum.
//!
//! After the FROST signing round produces a witnessed Bitcoin TM
//! transaction, the leader publishes it back to the Cardano treasury
//! oracle by **creating a new UTxO** at the treasury address with the
//! signed BTC tx as an inline datum:
//!
//! ```text
//! Constr(0, [signed_btc_tx, creator_pkh, created_ms, fulfilled_por_outpoints])
//! ```
//!
//! Constructor 0 = the `UnconfirmedTm` record — rev 5.4's ONLY TM datum
//! (Confirm burns the record; no Constr-1 `Confirmed` exists). The new
//! UTxO also carries 1 freshly-minted TM NFT: under the real
//! TreasuryMovementValidator policy the mint is permissionless but
//! gated by chain linkage — the redeemer carries the reference-input
//! index of the bridge-state singleton ([PTM-6]/[PTM-7]), the Config
//! UTxO rides along as a second reference input (the validator reads
//! `bridge_state_policy` from it, [PAR-1]), and the validator checks
//! the embedded BTC tx spends the singleton's `treasury_utxo_id`. The
//! always-ok scaffold policy (`ALWAYS_OK_PLUTUS_CBOR_HEX`) remains the
//! no-script fallback.
//!
//! The current treasury is the singleton's head — no Confirmed chain
//! walk exists any more.

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

/// The two reference inputs a real-validator TM post carries: the Config UTxO
/// and the bridge-state singleton, each as `(tx_hash_hex, output_index)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRefs {
    pub config: (String, u32),
    pub singleton: (String, u32),
}

impl MintRefs {
    /// The reference inputs in the order the LEDGER presents them to the script:
    /// sorted by (tx_hash bytes, index). The redeemer's singleton index must be
    /// computed against exactly this order, or `.at(i)` on-chain reads the wrong
    /// reference input.
    #[must_use]
    pub fn sorted(&self) -> Vec<(String, u32)> {
        let mut refs = vec![self.config.clone(), self.singleton.clone()];
        refs.sort();
        refs
    }

    /// 0-based position of the singleton among [`Self::sorted`].
    #[must_use]
    pub fn singleton_sorted_index(&self) -> u32 {
        u32::try_from(
            self.sorted()
                .iter()
                .position(|r| *r == self.singleton)
                .expect("singleton is in its own sorted set"),
        )
        .expect("two refs")
    }
}

/// Encode the `UnconfirmedTm` datum:
/// `Constr(constructor, [BoundedBytes(btc_tx), BoundedBytes(creator_pkh), BigInt(created_ms),
/// [BoundedBytes(outpoint_36) ..]])`.
///
/// Constructor 0 = the record's only shape (rev 5.4: no `Confirmed` variant;
/// the scaffold path may pass another tag). `creator` is the poster's payment
/// key hash (it may GC the record after the on-chain grace period); `created`
/// is POSIX ms, anchored by the TM mint policy to the tx's validity upper
/// bound. The rev-5.3 `epoch`/`leader_reward` fields LEFT the datum (spec
/// §Leader reward: DEFERRED).
///
/// Field 3 `fulfilled_por_outpoints` is the rev-5.1 data-availability HINT: the
/// Cardano outpoints (36 bytes each, tx hash ‖ output index LE) of the peg-out
/// requests this TM fulfils. Nothing on-chain reads it — neither the TM mint
/// branch nor the Confirm spend — because the FROST-signed BTMR1 root
/// commitment inside `btc_tx` is the sole integrity anchor. It exists so a cold
/// starting SPO can rebuild the completed-peg-outs trie from chain data alone:
/// the Unconfirmed record's inline datum survives in Cardano history forever and
/// is indexable by address, which transaction metadata is not.
///
/// The list is always written, empty included: a zero-peg-out TM writes `[]`.
///
/// Canonical encoding via `cardano::plutus::constr`.
fn encode_datum_hex(
    btc_tx: &[u8],
    constructor: u8,
    creator_pkh: &[u8],
    created_ms: i64,
    fulfilled_por_outpoints: &[[u8; 36]],
) -> String {
    let datum = crate::cardano::plutus::constr(
        u64::from(constructor),
        vec![
            crate::cardano::plutus::bytes(btc_tx),
            crate::cardano::plutus::bytes(creator_pkh),
            crate::cardano::plutus::int(created_ms),
            crate::cardano::plutus::array(
                fulfilled_por_outpoints
                    .iter()
                    .map(|op| crate::cardano::plutus::bytes(op))
                    .collect(),
            ),
        ],
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
    // The chain-linkage mint references `(config_utxo, singleton_utxo)` as `(tx_hash, index)`
    // pairs: the validator reads `bridge_state_policy` from the Config reference ([PAR-1]) and
    // checks the embedded BTC tx spends the singleton's head ([PTM-6]), authenticating the
    // singleton reference by its "BSS" NFT ([PTM-7]). Required alongside `tm_script_cbor`.
    mint_refs: Option<MintRefs>,
    // When `Some`, the network's live Plutus cost models `[V1, V2, V3]` (from Blockfrost). Used via
    // `Network::Custom` so the script-integrity hash matches the ledger's even when whisky's
    // hardcoded per-network cost models are stale. `None` → whisky's built-in Preprod models.
    cost_models: Option<Vec<Vec<i64>>>,
    // Latest chain `(slot, posix_secs)`: derives the tx's `invalid_hereafter` (slot + 30 min)
    // and the datum's `created`. The TM mint policy requires `created` to EQUAL the validity
    // upper bound's POSIX ms, making it a guaranteed upper bound on the real posting time (the
    // GC grace period can start late but never early). Block time == slot time and recent
    // preprod/mainnet slots are 1 s, so slot latest+1800 begins at (latest_time + 1800) s
    // exactly.
    latest_slot_time: (u64, i64),
    // Validity window (seconds): the tx's `invalid_hereafter` and the datum's `created` are both
    // `latest + validity_window_secs`. 1800 (30 min) on preprod/mainnet; MUST be small on a
    // short-epoch devnet, whose era-forecast horizon is only ~tens-to-hundreds of slots ahead —
    // a large window lands past it (TimeTranslationPastHorizon at submit).
    validity_window_secs: u64,
    // The rev-5.1 data-availability hint: the Cardano outpoints (36 bytes each) of the peg-out
    // requests this TM fulfils, straight from `UnsignedTm::fulfilled`. Pass an empty slice for a
    // TM that fulfils none — the field is written either way.
    fulfilled_por_outpoints: &[[u8; 36]],
) -> EpochResult<String> {
    let pkh = pub_key_hash_hex(key);
    let (latest_slot, latest_time_secs) = latest_slot_time;
    let created_ms = (latest_time_secs + validity_window_secs as i64) * 1000;
    let creator_pkh =
        hex::decode(&pkh).map_err(|e| EpochError::Chain(format!("wallet pkh decode: {e}")))?;
    let datum_hex = encode_datum_hex(
        signed_btc_tx,
        constructor,
        &creator_pkh,
        created_ms,
        fulfilled_por_outpoints,
    );
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
        // Reference the Config UTxO and the bridge-state singleton so the validator's mint
        // branch can verify the embedded BTC tx spends the singleton's head. The order here is
        // the SORTED order (see `MintRefs::sorted`) — the ledger presents reference inputs to
        // the script sorted by (tx_hash, index), and the redeemer's index points into that view.
        reference_inputs: mint_refs
            .as_ref()
            .map(|r| {
                r.sorted()
                    .into_iter()
                    .map(|(h, i)| RefTxIn {
                        tx_hash: h,
                        tx_index: i,
                        script_size: None,
                    })
                    .collect()
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
                // Real validator: TmMintRedeemer(bridgeStateRefInputIndex) = Constr(0, [i]),
                // where `i` is the singleton's position among the SORTED reference inputs
                // ([PTM-7] then authenticates it by the "BSS" NFT, so a wrong index fails
                // rather than misleads). Scaffold: unit.
                data: match (tm_script_cbor, mint_refs.as_ref()) {
                    (Some(_), Some(r)) => hex::encode(
                        minicbor::to_vec(&crate::cardano::plutus::constr(
                            0,
                            vec![crate::cardano::plutus::int(i64::from(
                                r.singleton_sorted_index(),
                            ))],
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
            // Finite upper bound, required by the TM mint policy's created-anchoring check:
            // `created` in the datum equals this slot's begin time in ms (see created_ms above).
            invalid_hereafter: Some(latest_slot + validity_window_secs),
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

    fn decode(hex_str: &str) -> pallas_primitives::conway::Constr<PlutusData> {
        let cbor = hex::decode(hex_str).unwrap();
        match pallas_codec::minicbor::decode::<PlutusData>(&cbor).expect("decode") {
            PlutusData::Constr(c) => c,
            _ => panic!("expected Constr"),
        }
    }

    #[test]
    fn encode_datum_is_constr_0_with_the_four_unconfirmed_fields() {
        let btc_tx = vec![0x02, 0x00, 0x00, 0x00];
        let creator = vec![0x7a; 28];
        let op1 = crate::cardano::cpo_trie::hint_bytes(&[0xaa; 32], 1);
        let op2 = crate::cardano::cpo_trie::hint_bytes(&[0xbb; 32], 0);
        let c = decode(&encode_datum_hex(
            &btc_tx,
            0,
            &creator,
            1_700_000_000_000,
            &[op1, op2],
        ));
        assert_eq!(c.tag, 121, "should be constructor 0 (UnconfirmedTm)");
        // rev 5.4: [signed_btc_tx, creator, created, fulfilled_por_outpoints] —
        // epoch/leader_reward LEFT the datum (spec §Leader reward: DEFERRED).
        assert_eq!(c.fields.len(), 4);
        match &c.fields[0] {
            PlutusData::BoundedBytes(b) => {
                let v: Vec<u8> = b.clone().into();
                assert_eq!(v, btc_tx);
            }
            _ => panic!("expected BoundedBytes"),
        }
        match &c.fields[1] {
            PlutusData::BoundedBytes(b) => {
                let v: Vec<u8> = b.clone().into();
                assert_eq!(v, creator);
            }
            _ => panic!("expected BoundedBytes creator"),
        }
        assert!(matches!(&c.fields[2], PlutusData::BigInt(_)), "created");
        match &c.fields[3] {
            PlutusData::Array(items) => assert_eq!(items.len(), 2),
            other => panic!("expected an Array of outpoints, got {other:?}"),
        }
    }

    // The redeemer's index must follow the LEDGER's sorted view of the reference
    // inputs, whichever way round the two UTxOs hash.
    #[test]
    fn the_singleton_index_follows_the_sorted_reference_inputs() {
        let config = ("aa".repeat(32), 0);
        let singleton = ("bb".repeat(32), 1);
        let r1 = MintRefs {
            config: config.clone(),
            singleton: singleton.clone(),
        };
        assert_eq!(r1.sorted(), vec![config.clone(), singleton.clone()]);
        assert_eq!(r1.singleton_sorted_index(), 1);
        let r2 = MintRefs {
            config: singleton.clone(),
            singleton: config.clone(),
        };
        assert_eq!(r2.singleton_sorted_index(), 0);
        // Same tx hash, different index: the index breaks the tie.
        let r3 = MintRefs {
            config: ("cc".repeat(32), 5),
            singleton: ("cc".repeat(32), 2),
        };
        assert_eq!(r3.singleton_sorted_index(), 0);
    }

    // The hint round-trips through the reader reconstruction uses, so what heimdall
    // writes is exactly what a cold-starting node reads back.
    #[test]
    fn the_written_hint_is_what_the_reconstruction_reader_parses() {
        let op1 = crate::cardano::cpo_trie::hint_bytes(&[0xaa; 32], 1);
        let op2 = crate::cardano::cpo_trie::hint_bytes(&[0xbb; 32], 7);
        let hex_str = encode_datum_hex(&[0x02], 0, &[0x7a; 28], 1, &[op1, op2]);
        let cbor = hex::decode(&hex_str).unwrap();
        let pd: PlutusData = pallas_codec::minicbor::decode(&cbor).unwrap();
        assert_eq!(
            crate::cardano::cpo_trie::unconfirmed_hint(&pd),
            vec![op1, op2]
        );
    }

    // A zero-peg-out TM still writes the field — as an empty list.
    #[test]
    fn a_zero_pegout_tm_writes_an_empty_hint_list() {
        let c = decode(&encode_datum_hex(&[0x02], 0, &[0x7a; 28], 1, &[]));
        assert_eq!(c.fields.len(), 4);
        match &c.fields[3] {
            PlutusData::Array(items) => assert!(items.is_empty()),
            other => panic!("expected an empty Array, got {other:?}"),
        }
    }
}
